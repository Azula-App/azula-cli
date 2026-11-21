mod common;

use std::time::Duration;

use common::*;
use serde_json::json;

fn expected_lines(n: usize) -> Vec<u8> {
    (1..=n)
        .flat_map(|i| format!("line{i}\n").into_bytes())
        .collect()
}

const COUNTER: &str = "for i in $(seq 1 40); do echo line$i; sleep 0.03; done";

#[test]
fn record_has_env_keys_never_values() {
    let env = start();
    let r = run(
        &env,
        merge(
            exec_req("g_a", &["true"]),
            json!({"env":{"AZ_SECRET_KEY":"hunter2-value"},"label":"build it"}),
        ),
    );
    let id = r.started.unwrap().header["job"]
        .as_str()
        .unwrap()
        .to_string();
    let dir = env.state_dir().join("jobs").join(&id);
    let rec = std::fs::read_to_string(dir.join("job.json")).unwrap();
    assert!(rec.contains("AZ_SECRET_KEY"));
    assert!(!rec.contains("hunter2-value"));
    assert!(rec.contains("build it"));
    assert!(dir.join("exit.json").exists());
    assert!(dir.join("stdout").is_dir() && dir.join("stderr").is_dir());
}

#[test]
fn idem_dedupe_runs_once_and_attaches_from_zero() {
    let env = start();
    let marker = env.files().join("runs");
    let script = format!("echo run >> {}; echo a; sleep 1; echo b", path_str(&marker));
    let req = exec_req("g_a", &["sh", "-c", &script]);
    let mut c1 = env.client();
    c1.send(merge(req.clone(), json!({"attach":false})), &[]);
    let f = c1.recv();
    assert_eq!(f.header["deduped"], false);
    let id = f.header["job"].clone();
    c1.expect_closed();

    // Same key again, attached: deduped, output from offset 0, one run.
    let mut c2 = env.client();
    c2.send(req.clone(), &[]);
    let r = c2.collect();
    let st = r.started.as_ref().unwrap();
    assert_eq!(st.header["deduped"], true);
    assert_eq!(st.header["job"], id);
    assert_eq!(r.stdout, b"a\nb\n");
    assert_eq!(r.h("code"), 0);
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "run\n");

    // attach:false on a dedupe just closes.
    let mut c3 = env.client();
    c3.send(merge(req, json!({"attach":false})), &[]);
    let f = c3.recv();
    assert_eq!(
        (f.t.as_str(), f.header["deduped"].clone()),
        ("started", json!(true))
    );
    c3.expect_closed();
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "run\n");
}

#[test]
fn idem_conflict_and_per_owner_scope() {
    let env = start();
    let req = exec_req("g_a", &["echo", "one"]);
    let r = run(&env, req.clone());
    assert_eq!(r.stdout, b"one\n");
    for changed in [
        json!({"argv":["echo","two"]}),
        json!({"cwd":"/"}),
        json!({"env":{"X":"1"}}),
        json!({"stdin":true}),
    ] {
        let r = run(&env, merge(req.clone(), changed.clone()));
        assert_eq!(r.last().t, "error", "{changed}");
        assert_eq!(r.h("code"), "idem_conflict", "{changed}");
    }
    // The same key from another owner is a different job.
    let r = run(&env, merge(req.clone(), json!({"owner":"g_b"})));
    assert_eq!(r.started.unwrap().header["deduped"], false);
    assert_eq!(r.stdout, b"one\n");
}

#[test]
fn reattach_exact_replay_plus_live() {
    let env = start();
    let mut c = env.client();
    c.send(exec_req("g_a", &["sh", "-c", COUNTER]), &[]);
    let id = c.recv().header["job"].as_str().unwrap().to_string();
    // Read a few frames, then lose the connection mid-job.
    let mut got = Vec::new();
    let mut next = 0u64;
    while next < 40 {
        let f = c.recv();
        assert_eq!(f.t, "stdout");
        assert_eq!(f.header["off"].as_u64().unwrap(), next);
        next += f.payload.len() as u64;
        got.extend_from_slice(&f.payload);
    }
    drop(c);
    // The job keeps running; reattach from where we were.
    let mut c = env.client();
    c.send(
        json!({"t":"attach","owner":"g_a","job":id,"stdout_off":next,"stderr_off":0,"follow":true}),
        &[],
    );
    let r = c.collect_from([next, 0]);
    assert_eq!(r.attached.as_ref().unwrap().header["state"], "running");
    got.extend_from_slice(&r.stdout);
    assert_eq!(got, expected_lines(40));
    assert_eq!(r.h("reason"), "exited");
    assert_eq!(r.h("stdout_len"), got.len() as u64);
    // Full replay of a finished job is identical.
    let mut c = env.client();
    c.send(
        json!({"t":"attach","owner":"g_a","job":id,"follow":false}),
        &[],
    );
    let r = c.collect();
    assert_eq!(r.stdout, expected_lines(40));
    assert_eq!(r.last().t, "exit");
}

#[test]
fn attach_follow_false_reports_end_while_running() {
    let env = start();
    let (id, _) = detach(&env, exec_req("g_a", &["sh", "-c", "echo first; sleep 30"]));
    wait_for("first line", 5, || {
        job_info(&env, "g_a", &id)["stdout_len"] == 6
    });
    let mut c = env.client();
    c.send(
        json!({"t":"attach","owner":"g_a","job":id,"follow":false}),
        &[],
    );
    let r = c.collect();
    assert_eq!(r.stdout, b"first\n");
    assert_eq!(r.last().t, "end");
    assert_eq!(r.h("state"), "running");
    assert_eq!(r.h("stdout_len"), 6);
    assert_eq!(r.h("stderr_len"), 0);
    cancel_job(&env, "g_a", &id);
}

#[test]
fn gap_after_forced_retention() {
    let env = start_with(|c| {
        c.segment_size = 1024;
        c.keep_segments = 2;
    });
    let (id, _) = detach(
        &env,
        exec_req("g_a", &["sh", "-c", "yes 0123456789abcdef | head -c 10240"]),
    );
    let info = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(info["stdout_len"], 10240);
    assert_eq!(info["stdout_earliest"], 8192);
    let mut c = env.client();
    c.send(
        json!({"t":"attach","owner":"g_a","job":id,"follow":false}),
        &[],
    );
    let r = c.collect();
    assert_eq!(r.gaps, vec![("stdout".to_string(), 0, 8192)]);
    assert_eq!(r.stdout.len(), 2048);
    let line = b"0123456789abcdef\n";
    for (i, b) in r.stdout.iter().enumerate() {
        assert_eq!(*b, line[(8192 + i) % line.len()]);
    }
    assert_eq!(r.h("stdout_len"), 10240);
    // Asking from inside the retained range gets no gap.
    let mut c = env.client();
    c.send(
        json!({"t":"attach","owner":"g_a","job":id,"stdout_off":9000,"follow":false}),
        &[],
    );
    let r = c.collect_from([9000, 0]);
    assert!(r.gaps.is_empty());
    assert_eq!(r.stdout.len(), 1240);
    // Only two segment files remain on disk.
    let n = std::fs::read_dir(env.state_dir().join("jobs").join(&id).join("stdout"))
        .unwrap()
        .count();
    assert_eq!(n, 2);
}

#[test]
fn live_client_gets_everything_despite_retention() {
    let env = start_with(|c| {
        c.segment_size = 1024;
        c.keep_segments = 2;
    });
    let r = run(
        &env,
        exec_req(
            "g_a",
            &["sh", "-c", "yes 0123456789abcdef | head -c 100000"],
        ),
    );
    // A live client may see a gap if it is slow, but never a hole: offsets
    // are checked contiguous by collect(), and the total adds up.
    let skipped: u64 = r.gaps.iter().map(|g| g.2 - g.1).sum();
    assert_eq!(r.stdout.len() as u64 + skipped, 100000);
}

#[test]
fn multiple_attachers_each_get_full_stream() {
    let env = start();
    let (id, _) = detach(&env, exec_req("g_a", &["sh", "-c", COUNTER]));
    let hs: Vec<_> = (0..3)
        .map(|_| {
            let port = env.port;
            let id = id.clone();
            std::thread::spawn(move || {
                let mut c = Client::connect(port);
                c.send(
                    json!({"t":"attach","owner":"g_a","job":id,"follow":true}),
                    &[],
                );
                c.collect()
            })
        })
        .collect();
    for h in hs {
        let r = h.join().unwrap();
        assert_eq!(r.stdout, expected_lines(40));
        assert_eq!(r.last().t, "exit");
    }
}

#[test]
fn stdin_lost_cancels_job() {
    let env = start();
    let mut c = env.client();
    c.send(merge(exec_req("g_a", &["cat"]), json!({"stdin":true})), &[]);
    let id = c.recv().header["job"].as_str().unwrap().to_string();
    c.send(json!({"t":"stdin"}), b"partial");
    drop(c);
    let j = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(j["reason"], "stdin_lost");
    assert!(j["code"].is_null());
}

#[test]
fn stdin_eof_then_disconnect_is_not_stdin_lost() {
    let env = start();
    let mut c = env.client();
    c.send(
        merge(
            exec_req("g_a", &["sh", "-c", "cat; sleep 1; echo done"]),
            json!({"stdin":true}),
        ),
        &[],
    );
    let id = c.recv().header["job"].as_str().unwrap().to_string();
    c.send(json!({"t":"stdin"}), b"x\n");
    c.send(json!({"t":"stdin_eof"}), &[]);
    drop(c);
    let j = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(j["reason"], "exited");
    assert_eq!(j["code"], 0);
}

#[test]
fn disconnect_does_not_cancel_without_flag() {
    let env = start_with(|c| c.orphan_after = Duration::from_millis(500));
    let mut c = env.client();
    c.send(exec_req("g_a", &["sleep", "7774"]), &[]);
    let id = c.recv().header["job"].as_str().unwrap().to_string();
    drop(c);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(job_info(&env, "g_a", &id)["state"], "running");
    assert!(pgrep("sleep 7774"));
    let f = cancel_job(&env, "g_a", &id);
    assert_eq!(f.t, "cancel_ok");
    assert_eq!(f.header["state"], "running");
    let j = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(j["reason"], "cancelled");
    wait_for("sleep to die", 5, || !pgrep("sleep 7774"));
    // Cancelling a finished job leaves it alone.
    let f = cancel_job(&env, "g_a", &id);
    assert_eq!(
        (f.t.as_str(), f.header["state"].clone()),
        ("cancel_ok", json!("exited"))
    );
    assert_eq!(job_info(&env, "g_a", &id)["reason"], "cancelled");
}

#[test]
fn cancel_on_disconnect_orphans_after_grace() {
    let env = start_with(|c| c.orphan_after = Duration::from_secs(1));
    // Detached from the start.
    let (id, _) = detach(
        &env,
        merge(
            exec_req("g_a", &["sleep", "7775"]),
            json!({"cancel_on_disconnect":true}),
        ),
    );
    let j = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(j["reason"], "orphaned");

    // Attached, then dropped: grace starts at the disconnect, and a
    // reattach inside the grace keeps the job alive.
    let mut c = env.client();
    c.send(
        merge(
            exec_req("g_a", &["sleep", "7776"]),
            json!({"cancel_on_disconnect":true}),
        ),
        &[],
    );
    let id = c.recv().header["job"].as_str().unwrap().to_string();
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        job_info(&env, "g_a", &id)["state"],
        "running",
        "still attached"
    );
    drop(c);
    std::thread::sleep(Duration::from_millis(300));
    let mut c2 = env.client();
    c2.send(
        json!({"t":"attach","owner":"g_a","job":id,"follow":true}),
        &[],
    );
    assert_eq!(c2.recv().t, "attached");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        job_info(&env, "g_a", &id)["state"],
        "running",
        "reattached in time"
    );
    drop(c2);
    let j = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(j["reason"], "orphaned");
}

#[test]
fn owner_isolation() {
    let env = start();
    let (a, _) = detach(
        &env,
        merge(exec_req("g_a", &["sleep", "7777"]), json!({"label":"mine"})),
    );
    let (b, _) = detach(&env, exec_req("g_b", &["sleep", "7778"]));
    let la = jobs(&env, "g_a");
    assert_eq!(la.len(), 1);
    assert_eq!(la[0]["job"], a);
    assert_eq!(la[0]["label"], "mine");
    assert_eq!(la[0]["state"], "running");
    assert!(la[0]["reason"].is_null() && la[0]["ended"].is_null());
    let all = jobs(&env, "*");
    assert_eq!(all.len(), 2);
    // Another owner's attach and cancel are indistinguishable from nonexistent.
    for (req_owner, id) in [("g_b", &a), ("g_a", &"j_0000000000000000".to_string())] {
        let mut c = env.client();
        c.send(json!({"t":"attach","owner":req_owner,"job":id}), &[]);
        let r = c.collect();
        assert_eq!(r.h("code"), "not_found");
        let f = cancel_job(&env, req_owner, id);
        assert_eq!(
            (f.t.as_str(), f.header["code"].clone()),
            ("error", json!("not_found"))
        );
    }
    assert_eq!(job_info(&env, "g_a", &a)["state"], "running");
    // The admin owner may cancel anything.
    let f = cancel_job(&env, "*", &b);
    assert_eq!(f.t, "cancel_ok");
    wait_state(&env, "g_b", &b, "exited");
    cancel_job(&env, "g_a", &a);
    wait_state(&env, "g_a", &a, "exited");
}

#[test]
fn cancel_frame_on_attach_connection() {
    let env = start();
    let (id, _) = detach(&env, exec_req("g_a", &["sleep", "7779"]));
    let mut c = env.client();
    c.send(json!({"t":"attach","owner":"g_a","job":id}), &[]);
    assert_eq!(c.recv().t, "attached");
    c.send(json!({"t":"cancel"}), &[]);
    let r = c.collect();
    assert_eq!(r.h("reason"), "cancelled");
}

#[test]
fn busy_caps() {
    let env = start_with(|c| {
        c.max_per_owner = 2;
        c.max_per_vm = 3;
    });
    let mut ids = vec![];
    for _ in 0..2 {
        ids.push(("g_a", detach(&env, exec_req("g_a", &["sleep", "7780"])).0));
    }
    let r = run(&env, exec_req("g_a", &["true"]));
    assert_eq!(r.h("code"), "busy");
    ids.push(("g_b", detach(&env, exec_req("g_b", &["sleep", "7780"])).0));
    let r = run(&env, exec_req("g_c", &["true"]));
    assert_eq!(r.h("code"), "busy", "per-VM cap");
    // Finished jobs don't count; cancelling frees a slot.
    cancel_job(&env, "g_a", &ids[0].1);
    wait_state(&env, "g_a", &ids[0].1, "exited");
    let r = run(&env, exec_req("g_a", &["echo", "ok"]));
    assert_eq!(r.stdout, b"ok\n");
    for (o, id) in ids {
        cancel_job(&env, o, &id);
    }
}

#[test]
fn retention_by_count() {
    let env = start_with(|c| c.max_finished = 3);
    let mut ids = vec![];
    for i in 0..5 {
        let r = run(&env, exec_req("g_a", &["echo", &i.to_string()]));
        ids.push(
            r.started.unwrap().header["job"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    wait_for("prune to 3", 5, || jobs(&env, "g_a").len() == 3);
    let kept: Vec<_> = jobs(&env, "g_a")
        .iter()
        .map(|j| j["job"].as_str().unwrap().to_string())
        .collect();
    // Newest first, oldest pruned.
    assert_eq!(kept, vec![ids[4].clone(), ids[3].clone(), ids[2].clone()]);
    assert!(!env.state_dir().join("jobs").join(&ids[0]).exists());
    assert!(env.state_dir().join("jobs").join(&ids[4]).exists());
}

#[test]
fn retention_by_age_and_running_jobs_survive() {
    let env = start_with(|c| c.max_age = Duration::from_secs(1));
    let (long, _) = detach(&env, exec_req("g_a", &["sleep", "7781"]));
    let r = run(&env, exec_req("g_a", &["echo", "old"]));
    let old = r.started.unwrap().header["job"]
        .as_str()
        .unwrap()
        .to_string();
    std::thread::sleep(Duration::from_millis(2200));
    // Any job start or finish triggers a prune.
    run(&env, exec_req("g_a", &["true"]));
    assert!(job_info(&env, "g_a", &old).is_null());
    assert_eq!(job_info(&env, "g_a", &long)["state"], "running");
    cancel_job(&env, "g_a", &long);
}

#[test]
fn retention_by_size() {
    let env = start_with(|c| c.max_bytes = 3000);
    let mut ids = vec![];
    for _ in 0..4 {
        let r = run(
            &env,
            exec_req("g_a", &["sh", "-c", "head -c 1000 /dev/zero"]),
        );
        ids.push(
            r.started.unwrap().header["job"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    wait_for("prune to 3", 5, || jobs(&env, "g_a").len() == 3);
    assert!(job_info(&env, "g_a", &ids[0]).is_null());
}

#[test]
fn disk_full_drops_output_but_job_finishes() {
    let env = start_with(|c| c.disk_limit = Some(100));
    // 2 MB would overflow the pipe buffer if the pump stopped draining.
    let (id, _) = detach(
        &env,
        exec_req(
            "g_a",
            &["sh", "-c", "head -c 2000000 /dev/zero; echo tail >&2"],
        ),
    );
    let j = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(j["code"], 0);
    assert_eq!(j["output_truncated"], true);
    assert!(j["stdout_len"].as_u64().unwrap() <= 100);
    let mut c = env.client();
    c.send(
        json!({"t":"attach","owner":"g_a","job":id,"follow":false}),
        &[],
    );
    let r = c.collect();
    assert_eq!(r.h("stdout_len"), j["stdout_len"]);
    assert_eq!(r.stdout.len() as u64, j["stdout_len"].as_u64().unwrap());
}

#[test]
fn slow_attacher_never_blocks_the_job() {
    let env = start();
    let mut c = env.client();
    c.send(
        exec_req(
            "g_a",
            &[
                "sh",
                "-c",
                "yes 0123456789abcdef | head -c 20000000; echo fin >&2",
            ],
        ),
        &[],
    );
    let id = c.recv().header["job"].as_str().unwrap().to_string();
    // Never read from `c`; the job must finish anyway.
    let j = wait_state(&env, "g_a", &id, "exited");
    assert_eq!(j["stdout_len"], 20000000);
    drop(c);
}
