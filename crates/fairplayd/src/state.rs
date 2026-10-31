//! The daemon's bookkeeping: who may launch, as whom the game runs, which
//! sessions exist, who may see them, and the PROTECTED map entries that go
//! with them. No syscalls here except through [`ProtectedMap`], so all of it
//! is unit-tested without BPF or root.

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use fairplay_api::{
    ApiError, ErrorCode, ProcessInfo, ProcessState, Reply, SessionId, SessionInfo, ViolationEvent,
};
use fairplay_common::{ExecAllow, ExecKey, Hook, Violation};

use crate::exec_allow::{ExecEntries, FileId};

/// The kernel's PROTECTED map (tgid -> protection domain) and EXEC_ALLOWED
/// map (files a domain may map executable), or a fake in tests.
pub trait ProtectedMap {
    fn insert(&mut self, pid: u32, domain: u32) -> Result<()>;
    fn remove(&mut self, pid: u32) -> Result<()>;
    fn allow_exec(&mut self, key: ExecKey, value: ExecAllow) -> Result<()>;
    fn disallow_exec(&mut self, key: ExecKey) -> Result<()>;
}

/// Who is on the other end of a connection, as the kernel reported it
/// (`SO_PEERCRED`, `SO_PEERGROUPS`) when it connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

impl Peer {
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

/// The credentials a launched program gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

/// Domain for processes given on fairplayd's command line (milestone 3).
pub const CLI_DOMAIN: u32 = 1;
/// Running protected processes one launcher may have. Keeps one user from
/// filling the PROTECTED map (1024 entries) and locking everyone else out.
pub const MAX_RUNNING_PER_LAUNCHER: usize = 16;
/// Running protected processes in total; leaves room in the map for
/// command-line PIDs.
pub const MAX_RUNNING: usize = 512;
/// Ended sessions kept for status queries; the oldest are forgotten first.
pub const MAX_ENDED_KEPT: usize = 256;

/// Decides whether `peer` may call `launch_protected` and, if so, whom the
/// program runs as.
///
/// - Launchers are root and members of the launcher group (`launcher_gid`,
///   primary or supplementary). Everyone else gets `forbidden`.
/// - A non-root launcher's program runs as the launcher, minus the launcher
///   group (the game has no business launching protected processes). It
///   may not ask for another uid.
/// - Root must name the uid (`run_as`); its gid and groups come from the
///   user database via `lookup`. Nothing runs as root unless root asks for
///   uid 0 explicitly.
pub fn launch_identity(
    peer: &Peer,
    launcher_gid: Option<u32>,
    run_as: Option<u32>,
    lookup: impl FnOnce(u32) -> Option<(u32, Vec<u32>)>,
) -> Result<Identity, ApiError> {
    let in_group = |g: u32| peer.gid == g || peer.groups.contains(&g);
    let drop_launcher = |groups: Vec<u32>| -> Vec<u32> {
        groups
            .into_iter()
            .filter(|&g| Some(g) != launcher_gid)
            .collect()
    };
    if peer.is_root() {
        let Some(uid) = run_as else {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "root must say which uid the program runs as (run_as); it never defaults to root",
            ));
        };
        let Some((gid, groups)) = lookup(uid) else {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("uid {uid} is not in the user database"),
            ));
        };
        return Ok(Identity {
            uid,
            gid,
            groups: drop_launcher(groups),
        });
    }
    if !launcher_gid.is_some_and(in_group) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "launch_protected is for launchers only (root or the launcher group)",
        ));
    }
    if run_as.is_some_and(|u| u != peer.uid) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "only root may launch as another user",
        ));
    }
    Ok(Identity {
        uid: peer.uid,
        gid: peer.gid,
        groups: drop_launcher(peer.groups.clone()),
    })
}

#[derive(Debug)]
struct Proc {
    pid: u32,
    argv: Vec<String>,
    state: ProcessState,
}

impl Proc {
    fn running(&self) -> bool {
        self.state == ProcessState::Running
    }

    fn info(&self) -> ProcessInfo {
        ProcessInfo {
            pid: self.pid,
            argv: self.argv.clone(),
            state: self.state,
        }
    }
}

/// A game and the processes launched into its protection domain.
#[derive(Debug)]
struct Session {
    launcher_uid: u32,
    uid: u32,
    domain: u32,
    game: Proc,
    members: Vec<Proc>,
    started_at: u64,
    violations: u64,
}

impl Session {
    fn procs(&self) -> impl Iterator<Item = &Proc> {
        std::iter::once(&self.game).chain(&self.members)
    }

    fn procs_mut(&mut self) -> impl Iterator<Item = &mut Proc> {
        std::iter::once(&mut self.game).chain(&mut self.members)
    }

    fn info(&self, id: SessionId) -> SessionInfo {
        SessionInfo {
            session: id,
            launcher_uid: self.launcher_uid,
            uid: self.uid,
            game: self.game.info(),
            members: self.members.iter().map(Proc::info).collect(),
            started_at: self.started_at,
            violations: self.violations,
        }
    }
}

/// A launch that passed the checks and has a session and domain reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub session: SessionId,
    pub domain: u32,
    /// Joining an existing session rather than starting one.
    pub join: bool,
}

/// What a `violations` subscriber receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subscription {
    Session(SessionId),
    /// Root only: every protected process, including command-line ones.
    All,
}

impl Subscription {
    pub fn wants(&self, ev: &ViolationEvent) -> bool {
        match self {
            Subscription::All => true,
            Subscription::Session(id) => ev.session == Some(*id),
        }
    }
}

pub struct Daemon<M> {
    map: M,
    sessions: BTreeMap<SessionId, Session>,
    next_session: SessionId,
    next_domain: u32,
    /// What this daemon put in EXEC_ALLOWED, per domain (milestone 8).
    exec: ExecEntries,
}

impl<M: ProtectedMap> Daemon<M> {
    pub fn new(map: M) -> Self {
        Self {
            map,
            sessions: BTreeMap::new(),
            next_session: 1,
            next_domain: CLI_DOMAIN + 1,
            exec: ExecEntries::default(),
        }
    }

    pub fn map_mut(&mut self) -> &mut M {
        &mut self.map
    }

    /// Lets every protected process map these files executable (approved
    /// overlays). For startup: an error means fairplayd shouldn't start.
    pub fn allow_overlays(&mut self, files: &[FileId]) -> Result<(), ApiError> {
        self.exec
            .allow(&mut self.map, fairplay_common::ANY_DOMAIN, files)
            .map(|_| ())
    }

    /// Adds a launch's files to its domain's allowlist before the program
    /// runs. Returns how many were new. Refuses (and adds nothing) if the
    /// map can't take them all.
    pub fn allow_exec(&mut self, t: &Ticket, files: &[FileId]) -> Result<usize, ApiError> {
        self.exec.allow(&mut self.map, t.domain, files)
    }

    /// Undoes [`Daemon::allow_exec`] for a launch that started a session but
    /// failed before registering it.
    pub fn abandon_launch(&mut self, t: &Ticket) {
        if !t.join {
            self.exec.release(&mut self.map, t.domain);
        }
    }

    /// Entries in EXEC_ALLOWED that this daemon made (for tests and logs).
    pub fn exec_entries(&self) -> usize {
        self.exec.used()
    }

    /// Checks limits and reserves a session and protection domain: a new
    /// one, or with `join`, the existing session's. Each session is its own
    /// domain, so two protected games can't read each other either.
    pub fn begin_launch(
        &mut self,
        peer: &Peer,
        join: Option<SessionId>,
    ) -> Result<Ticket, ApiError> {
        let (total, mine) = self
            .sessions
            .values()
            .flat_map(|s| {
                s.procs()
                    .filter(|p| p.running())
                    .map(move |_| s.launcher_uid)
            })
            .fold((0, 0), |(t, m), uid| {
                (t + 1, m + usize::from(uid == peer.uid))
            });
        if total >= MAX_RUNNING {
            return Err(ApiError::new(
                ErrorCode::LimitReached,
                "too many protected processes",
            ));
        }
        if mine >= MAX_RUNNING_PER_LAUNCHER && !peer.is_root() {
            return Err(ApiError::new(
                ErrorCode::LimitReached,
                format!(
                    "at most {MAX_RUNNING_PER_LAUNCHER} running protected processes per launcher"
                ),
            ));
        }
        if let Some(id) = join {
            // Only the session's launcher (or root) may add to its domain:
            // being in the domain means being able to read the game.
            let s = match self.sessions.get(&id) {
                Some(s) if peer.is_root() || s.launcher_uid == peer.uid => s,
                _ => return Err(not_found(id)),
            };
            if !s.game.running() {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    format!("session {id} has ended"),
                ));
            }
            return Ok(Ticket {
                session: id,
                domain: s.domain,
                join: true,
            });
        }
        let t = Ticket {
            session: self.next_session,
            domain: self.next_domain,
            join: false,
        };
        self.next_session += 1;
        self.next_domain = self.next_domain.checked_add(1).unwrap_or(CLI_DOMAIN + 1);
        Ok(t)
    }

    /// Puts a freshly forked (not yet released) child into PROTECTED and
    /// records it. The caller must not let the child exec unless this
    /// succeeds.
    pub fn register(
        &mut self,
        t: Ticket,
        pid: u32,
        launcher: &Peer,
        runs_as: u32,
        argv: Vec<String>,
    ) -> Result<()> {
        let proc = Proc {
            pid,
            argv,
            state: ProcessState::Running,
        };
        if t.join {
            let s = self
                .sessions
                .get_mut(&t.session)
                .ok_or_else(|| anyhow::anyhow!("session {} vanished", t.session))?;
            self.map.insert(pid, t.domain)?;
            s.members.push(proc);
        } else {
            self.map.insert(pid, t.domain)?;
            self.sessions.insert(
                t.session,
                Session {
                    launcher_uid: launcher.uid,
                    uid: runs_as,
                    domain: t.domain,
                    game: proc,
                    members: vec![],
                    started_at: now(),
                    violations: 0,
                },
            );
        }
        Ok(())
    }

    /// A child has exited but is not reaped yet, so its PID can't have been
    /// reused. Drop it from PROTECTED now, before the reap frees the PID.
    /// Returns its session, if it was one of ours.
    pub fn child_exited(&mut self, pid: u32, state: ProcessState) -> Option<SessionId> {
        let (&id, s) = self
            .sessions
            .iter_mut()
            .find(|(_, s)| s.procs().any(|p| p.pid == pid && p.running()))?;
        let p = s.procs_mut().find(|p| p.pid == pid && p.running())?;
        if let Err(e) = self.map.remove(pid) {
            eprintln!("fairplayd: removing pid {pid} from PROTECTED: {e:#}");
        }
        p.state = state;
        // The domain's last process is gone: its files are no longer
        // allowed (domains aren't reused while the daemon runs, but the map
        // is finite).
        if !s.procs().any(Proc::running) {
            self.exec.release(&mut self.map, s.domain);
        }
        self.prune_ended();
        Some(id)
    }

    fn prune_ended(&mut self) {
        let ended: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, s)| !s.procs().any(Proc::running))
            .map(|(&id, _)| id)
            .collect();
        for id in ended
            .iter()
            .take(ended.len().saturating_sub(MAX_ENDED_KEPT))
        {
            self.sessions.remove(id);
        }
    }

    /// The session a running protected process belongs to.
    pub fn session_of_pid(&self, pid: u32) -> Option<SessionId> {
        self.sessions
            .iter()
            .find(|(_, s)| s.procs().any(|p| p.pid == pid && p.running()))
            .map(|(&id, _)| id)
    }

    /// Turns a kernel record into an event, filed under the session whose
    /// process it targeted. A record can arrive just after the target
    /// exited, so ended processes count too; the newest session wins (PIDs
    /// are reused only after we reap, which is after we stop protecting).
    pub fn record_violation(&mut self, v: &Violation, exe_path: Option<String>) -> ViolationEvent {
        let session = self
            .sessions
            .iter_mut()
            .rev()
            .find(|(_, s)| s.procs().any(|p| p.pid == v.target))
            .map(|(&id, s)| {
                s.violations += 1;
                id
            });
        ViolationEvent {
            session,
            caller: v.caller,
            comm: c_str(&v.comm),
            exe: c_str(&v.exe),
            exe_path,
            target: v.target,
            hook: hook_name(v.hook).into(),
            mode: v.mode,
            file: Some(c_str(&v.file)).filter(|f| !f.is_empty()),
            seen_at: now(),
        }
    }

    /// May `peer` see this session? Root; its launcher; the uid it runs as;
    /// or one of its own running processes (the anti-cheat asking about
    /// the game it sits next to).
    fn visible(&self, peer: &Peer, id: SessionId) -> Result<&Session, ApiError> {
        match self.sessions.get(&id) {
            Some(s)
                if peer.is_root()
                    || s.launcher_uid == peer.uid
                    || s.uid == peer.uid
                    || s.procs().any(|p| p.pid == peer.pid && p.running()) =>
            {
                Ok(s)
            }
            // Same answer whether it doesn't exist or isn't yours.
            _ => Err(not_found(id)),
        }
    }

    /// (protected, session) for `session_status`. Without an id, the
    /// session the caller's process belongs to, if any.
    pub fn status(
        &self,
        peer: &Peer,
        id: Option<SessionId>,
    ) -> Result<(bool, Option<SessionInfo>), ApiError> {
        let Some(id) = id.or_else(|| self.session_of_pid(peer.pid)) else {
            return Ok((false, None));
        };
        let s = self.visible(peer, id)?;
        Ok((s.game.running(), Some(s.info(id))))
    }

    pub fn subscribe(&self, peer: &Peer, id: Option<SessionId>) -> Result<Subscription, ApiError> {
        match id.or_else(|| self.session_of_pid(peer.pid)) {
            Some(id) => self.visible(peer, id).map(|_| Subscription::Session(id)),
            None if peer.is_root() => Ok(Subscription::All),
            None => Err(ApiError::new(
                ErrorCode::NotFound,
                "not in a protected session; name one",
            )),
        }
    }

    pub fn list(&self, peer: &Peer) -> Reply {
        Reply::Sessions(
            self.sessions
                .keys()
                .filter_map(|&id| self.visible(peer, id).ok().map(|s| s.info(id)))
                .collect(),
        )
    }
}

fn not_found(id: SessionId) -> ApiError {
    ApiError::new(ErrorCode::NotFound, format!("no session {id}"))
}

pub fn hook_name(hook: u32) -> &'static str {
    match hook {
        x if x == Hook::PtraceAccess as u32 => "ptrace_access_check",
        x if x == Hook::UinputOpen as u32 => "file_open(/dev/uinput)",
        x if x == Hook::MmapFile as u32 => "mmap_file",
        x if x == Hook::FileMprotect as u32 => "file_mprotect",
        _ => "unknown",
    }
}

/// A NUL-padded kernel string.
pub fn c_str(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use fairplay_common::{EXEC_CHECK_GENERATION, EXE_NAME_LEN};

    use super::*;

    #[derive(Default)]
    struct FakeMap {
        entries: HashMap<u32, u32>,
        fail_insert: bool,
        exec: HashMap<ExecKey, ExecAllow>,
        /// Fail exec inserts once this many entries exist.
        exec_fail_at: Option<usize>,
    }

    impl ProtectedMap for FakeMap {
        fn insert(&mut self, pid: u32, domain: u32) -> Result<()> {
            anyhow::ensure!(!self.fail_insert, "map full");
            self.entries.insert(pid, domain);
            Ok(())
        }
        fn remove(&mut self, pid: u32) -> Result<()> {
            self.entries.remove(&pid);
            Ok(())
        }
        fn allow_exec(&mut self, key: ExecKey, value: ExecAllow) -> Result<()> {
            anyhow::ensure!(
                self.exec_fail_at.is_none_or(|n| self.exec.len() < n),
                "map full"
            );
            self.exec.insert(key, value);
            Ok(())
        }
        fn disallow_exec(&mut self, key: ExecKey) -> Result<()> {
            self.exec.remove(&key);
            Ok(())
        }
    }

    fn file(ino: u64) -> FileId {
        FileId {
            dev: 7,
            ino,
            generation: ino.is_multiple_of(2).then_some(ino as u32 + 100),
        }
    }

    #[test]
    fn exec_allowlist_follows_the_session() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        let t = d.begin_launch(&alice, None).unwrap();
        assert_eq!(d.allow_exec(&t, &[file(1), file(2), file(2)]).unwrap(), 2);
        d.register(t, 4242, &alice, 1000, vec!["game".into()])
            .unwrap();
        let k = |ino| ExecKey {
            domain: t.domain,
            dev: 7,
            ino,
        };
        assert_eq!(
            d.map.exec[&k(1)],
            ExecAllow {
                generation: 0,
                flags: 0
            }
        );
        assert_eq!(
            d.map.exec[&k(2)],
            ExecAllow {
                generation: 102,
                flags: EXEC_CHECK_GENERATION
            }
        );
        // The anti-cheat joins with its own files; repeats aren't counted.
        let j = d.begin_launch(&alice, Some(t.session)).unwrap();
        assert_eq!(d.allow_exec(&j, &[file(2), file(3)]).unwrap(), 1);
        d.register(j, 4243, &alice, 1000, vec!["ac".into()])
            .unwrap();
        assert_eq!(d.exec_entries(), 3);
        // Entries stay while any process of the session runs.
        d.child_exited(4242, EXITED_0);
        assert_eq!(d.map.exec.len(), 3);
        d.child_exited(4243, EXITED_0);
        assert!(d.map.exec.is_empty());
        assert_eq!(d.exec_entries(), 0);
    }

    #[test]
    fn overlays_are_for_every_domain_and_stay() {
        let mut d = Daemon::new(FakeMap::default());
        d.allow_overlays(&[file(9)]).unwrap();
        assert!(d.map.exec.contains_key(&ExecKey {
            domain: fairplay_common::ANY_DOMAIN,
            dev: 7,
            ino: 9
        }));
        let alice = launcher(1000);
        let t = launch(&mut d, &alice, 4242);
        d.allow_exec(&t, &[file(1)]).unwrap();
        d.child_exited(4242, EXITED_0);
        assert_eq!(d.map.exec.len(), 1, "the overlay outlives sessions");
    }

    #[test]
    fn a_full_allowlist_refuses_the_launch_and_adds_nothing() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        // The kernel map fails part-way: everything from this call is undone.
        d.map.exec_fail_at = Some(2);
        let t = d.begin_launch(&alice, None).unwrap();
        let e = d.allow_exec(&t, &[file(1), file(2), file(3)]).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert!(d.map.exec.is_empty());
        assert_eq!(d.exec_entries(), 0);
        // Over capacity: refused up front.
        d.map.exec_fail_at = None;
        let many: Vec<FileId> = (0..fairplay_common::EXEC_ALLOWED_CAPACITY as u64 + 1)
            .map(file)
            .collect();
        let e = d.allow_exec(&t, &many).unwrap_err();
        assert_eq!(e.code, ErrorCode::LimitReached);
        assert!(d.map.exec.is_empty());
        // A launch that fails before registering gives its entries back.
        d.allow_exec(&t, &[file(1)]).unwrap();
        d.abandon_launch(&t);
        assert!(d.map.exec.is_empty());
    }

    const LAUNCHERS: u32 = 900;

    fn user(uid: u32) -> Peer {
        Peer {
            pid: 100_000 + uid,
            uid,
            gid: uid,
            groups: vec![uid],
        }
    }

    fn launcher(uid: u32) -> Peer {
        let mut p = user(uid);
        p.groups.push(LAUNCHERS);
        p
    }

    fn launch(d: &mut Daemon<FakeMap>, peer: &Peer, pid: u32) -> Ticket {
        let t = d.begin_launch(peer, None).unwrap();
        d.register(t, pid, peer, peer.uid, vec!["game".into()])
            .unwrap();
        t
    }

    fn denied(caller: u32, target: u32) -> Violation {
        let mut comm = [0u8; 16];
        comm[..8].copy_from_slice(b"cheatsim");
        let mut exe = [0u8; EXE_NAME_LEN];
        exe[..8].copy_from_slice(b"cheatsim");
        Violation {
            caller,
            target,
            hook: Hook::PtraceAccess as u32,
            mode: 0x11,
            comm,
            exe,
            file: [0; EXE_NAME_LEN],
        }
    }

    const EXITED_0: ProcessState = ProcessState::Exited {
        code: Some(0),
        signal: None,
    };

    fn no_lookup(_: u32) -> Option<(u32, Vec<u32>)> {
        panic!("lookup must not be used for non-root launchers")
    }

    #[test]
    fn only_launchers_may_launch() {
        let e = launch_identity(&user(1000), Some(LAUNCHERS), None, no_lookup).unwrap_err();
        assert_eq!(e.code, ErrorCode::Forbidden);
        // No launcher group configured: only root.
        let e = launch_identity(&launcher(1000), None, None, no_lookup).unwrap_err();
        assert_eq!(e.code, ErrorCode::Forbidden);
        // Primary group counts too.
        let mut p = user(1000);
        p.gid = LAUNCHERS;
        assert!(launch_identity(&p, Some(LAUNCHERS), None, no_lookup).is_ok());
    }

    #[test]
    fn launcher_runs_game_as_itself_without_launcher_group() {
        let id = launch_identity(&launcher(1000), Some(LAUNCHERS), None, no_lookup).unwrap();
        assert_eq!(
            id,
            Identity {
                uid: 1000,
                gid: 1000,
                groups: vec![1000]
            }
        );
        assert!(launch_identity(&launcher(1000), Some(LAUNCHERS), Some(1000), no_lookup).is_ok());
        for other in [0, 1001] {
            let e = launch_identity(&launcher(1000), Some(LAUNCHERS), Some(other), no_lookup)
                .unwrap_err();
            assert_eq!(e.code, ErrorCode::Forbidden, "run_as {other}");
        }
    }

    #[test]
    fn root_must_name_a_user() {
        let root = user(0);
        let lookup = |uid| (uid == 1000).then(|| (1000, vec![1000, 27, LAUNCHERS]));
        let e = launch_identity(&root, Some(LAUNCHERS), None, lookup).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest, "never root by default");
        let id = launch_identity(&root, Some(LAUNCHERS), Some(1000), lookup).unwrap();
        assert_eq!((id.uid, id.gid, id.groups), (1000, 1000, vec![1000, 27]));
        let e = launch_identity(&root, Some(LAUNCHERS), Some(4242), lookup).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest);
        // Explicitly asking for root is allowed (root could do it anyway).
        let id = launch_identity(&root, None, Some(0), |_| Some((0, vec![0]))).unwrap();
        assert_eq!(id.uid, 0);
    }

    #[test]
    fn launch_protects_and_exit_unprotects() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        let t = launch(&mut d, &alice, 4242);
        assert_eq!(d.map.entries.get(&4242), Some(&t.domain));
        assert_ne!(t.domain, CLI_DOMAIN);
        assert!(d.status(&alice, Some(t.session)).unwrap().0);

        assert_eq!(d.child_exited(4242, EXITED_0), Some(t.session));
        assert!(d.map.entries.is_empty(), "exited pid must leave PROTECTED");
        let (protected, info) = d.status(&alice, Some(t.session)).unwrap();
        assert!(!protected);
        assert_eq!(info.unwrap().game.state, EXITED_0);
        // A second exit report for the same pid (or one we never launched)
        // touches nothing.
        assert_eq!(d.child_exited(4242, EXITED_0), None);
        assert_eq!(d.child_exited(7, EXITED_0), None);
    }

    #[test]
    fn exit_leaves_other_entries_alone() {
        let mut d = Daemon::new(FakeMap::default());
        d.map.insert(55, CLI_DOMAIN).unwrap(); // from --protect
        let t1 = launch(&mut d, &launcher(1000), 10);
        let t2 = launch(&mut d, &launcher(1000), 11);
        assert_ne!(t1.domain, t2.domain, "each session is its own domain");
        d.child_exited(10, EXITED_0);
        assert_eq!(d.map.entries.len(), 2);
        assert!(d.map.entries.contains_key(&55) && d.map.entries.contains_key(&11));
    }

    #[test]
    fn failed_insert_registers_nothing() {
        let mut d = Daemon::new(FakeMap {
            fail_insert: true,
            ..Default::default()
        });
        let alice = launcher(1000);
        let t = d.begin_launch(&alice, None).unwrap();
        assert!(d.register(t, 9, &alice, 1000, vec![]).is_err());
        let e = d.status(&alice, Some(t.session)).unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }

    #[test]
    fn anti_cheat_joins_the_game_domain() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        let t = launch(&mut d, &alice, 50);
        let j = d.begin_launch(&alice, Some(t.session)).unwrap();
        assert_eq!((j.session, j.domain, j.join), (t.session, t.domain, true));
        d.register(j, 51, &alice, 1000, vec!["ac".into()]).unwrap();
        assert_eq!(d.map.entries.get(&51), Some(&t.domain));

        // The anti-cheat, asking about "my session", finds the game's.
        let ac = Peer {
            pid: 51,
            ..user(1000)
        };
        let (protected, info) = d.status(&ac, None).unwrap();
        assert!(protected);
        let info = info.unwrap();
        assert_eq!((info.game.pid, info.members[0].pid), (50, 51));
        assert_eq!(
            d.subscribe(&ac, None).unwrap(),
            Subscription::Session(t.session)
        );

        // Its exit unprotects it and leaves the game alone.
        assert_eq!(d.child_exited(51, EXITED_0), Some(t.session));
        assert_eq!(d.map.entries.len(), 1);
        assert!(d.status(&alice, Some(t.session)).unwrap().0);

        // Once the game is gone nobody joins.
        d.child_exited(50, EXITED_0);
        let e = d.begin_launch(&alice, Some(t.session)).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest);
    }

    #[test]
    fn only_the_launcher_may_join() {
        let mut d = Daemon::new(FakeMap::default());
        let t = launch(&mut d, &launcher(1000), 60);
        for peer in [launcher(1001), user(1001)] {
            let e = d.begin_launch(&peer, Some(t.session)).unwrap_err();
            assert_eq!(e.code, ErrorCode::NotFound);
        }
        assert!(d.begin_launch(&user(0), Some(t.session)).is_ok());
        assert_eq!(
            d.begin_launch(&user(0), Some(99)).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn users_only_see_their_own_sessions() {
        let mut d = Daemon::new(FakeMap::default());
        let (alice, bob, root) = (launcher(1000), launcher(1001), user(0));
        let a = launch(&mut d, &alice, 20).session;
        let b = launch(&mut d, &bob, 21).session;

        assert!(d.status(&alice, Some(a)).is_ok());
        assert!(d.subscribe(&alice, Some(a)).is_ok());
        // The game's uid (here also alice) without the launcher group, too.
        assert!(d.status(&user(1000), Some(a)).is_ok());
        assert_eq!(
            d.status(&alice, Some(b)).unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            d.subscribe(&alice, Some(b)).unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            d.status(&bob, Some(a)).unwrap_err().code,
            ErrorCode::NotFound
        );
        // Someone else's session and a missing one look the same.
        assert_eq!(
            d.status(&alice, Some(b)).unwrap_err().message,
            d.status(&alice, Some(999))
                .unwrap_err()
                .message
                .replace("999", &b.to_string())
        );
        assert!(d.status(&root, Some(a)).is_ok() && d.status(&root, Some(b)).is_ok());

        let ids = |r: Reply| match r {
            Reply::Sessions(v) => v.into_iter().map(|s| s.session).collect::<Vec<_>>(),
            r => panic!("{r:?}"),
        };
        assert_eq!(ids(d.list(&alice)), vec![a]);
        assert_eq!(ids(d.list(&bob)), vec![b]);
        assert_eq!(ids(d.list(&root)), vec![a, b]);
    }

    #[test]
    fn status_and_subscribe_without_a_session() {
        let d = Daemon::new(FakeMap::default());
        assert_eq!(d.status(&user(1000), None).unwrap(), (false, None));
        let e = d.subscribe(&user(1000), None).unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
        assert_eq!(d.subscribe(&user(0), None).unwrap(), Subscription::All);
    }

    #[test]
    fn violations_go_to_the_targeted_session() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        let a = launch(&mut d, &alice, 30).session;
        let b = launch(&mut d, &alice, 31).session;
        for _ in 0..3 {
            let ev = d.record_violation(&denied(666, 30), Some("/usr/bin/cheatsim".into()));
            assert_eq!(ev.session, Some(a));
            assert_eq!(
                (ev.comm.as_str(), ev.exe.as_str()),
                ("cheatsim", "cheatsim")
            );
            assert_eq!(ev.hook, "ptrace_access_check");
            assert_eq!((ev.caller, ev.target, ev.mode), (666, 30, 0x11));
            assert!(Subscription::Session(a).wants(&ev));
            assert!(!Subscription::Session(b).wants(&ev));
            assert!(Subscription::All.wants(&ev));
        }
        let stray = d.record_violation(&denied(666, 99), None);
        assert_eq!(stray.session, None, "a --protect pid, not a session");
        assert!(!Subscription::Session(a).wants(&stray));
        assert!(Subscription::All.wants(&stray));

        assert_eq!(d.status(&alice, Some(a)).unwrap().1.unwrap().violations, 3);
        assert_eq!(d.status(&alice, Some(b)).unwrap().1.unwrap().violations, 0);
        // Records that arrive after the game exited still count.
        d.child_exited(30, EXITED_0);
        assert_eq!(d.record_violation(&denied(666, 30), None).session, Some(a));
    }

    #[test]
    fn per_launcher_limit() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        for pid in 0..MAX_RUNNING_PER_LAUNCHER as u32 {
            launch(&mut d, &alice, 1000 + pid);
        }
        let e = d.begin_launch(&alice, None).unwrap_err();
        assert_eq!(e.code, ErrorCode::LimitReached);
        assert!(
            d.begin_launch(&launcher(1001), None).is_ok(),
            "others unaffected"
        );
        d.child_exited(1000, EXITED_0);
        assert!(
            d.begin_launch(&alice, None).is_ok(),
            "exited processes don't count"
        );
    }

    #[test]
    fn ended_sessions_are_pruned_oldest_first() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        let first = launch(&mut d, &alice, 1).session;
        d.child_exited(1, EXITED_0);
        for pid in 2..(MAX_ENDED_KEPT as u32 + 2) {
            launch(&mut d, &alice, pid);
            d.child_exited(pid, EXITED_0);
        }
        let e = d.status(&alice, Some(first)).unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
        assert!(d.status(&alice, Some(first + 1)).is_ok());
    }

    #[test]
    fn kernel_strings_and_hook_names() {
        assert_eq!(c_str(b"cat\0\0\0\0\0\0\0\0\0\0\0\0\0"), "cat");
        assert_eq!(c_str(b"0123456789abcdef"), "0123456789abcdef");
        assert_eq!(hook_name(Hook::UinputOpen as u32), "file_open(/dev/uinput)");
        assert_eq!(hook_name(77), "unknown");
    }

    #[test]
    fn mapping_violations_name_the_file() {
        let mut d = Daemon::new(FakeMap::default());
        let alice = launcher(1000);
        let t = launch(&mut d, &alice, 4242);
        // The game itself tried: caller and target are both the game.
        let mut v = denied(4242, 4242);
        v.hook = Hook::MmapFile as u32;
        v.mode = 0x5;
        v.file[..8].copy_from_slice(b"cheat.so");
        let ev = d.record_violation(&v, None);
        assert_eq!(ev.session, Some(t.session));
        assert_eq!(ev.hook, "mmap_file");
        assert_eq!(ev.file.as_deref(), Some("cheat.so"));
        assert_eq!(hook_name(Hook::FileMprotect as u32), "file_mprotect");
        // Process hooks have no file.
        assert_eq!(d.record_violation(&denied(1, 4242), None).file, None);
    }
}
