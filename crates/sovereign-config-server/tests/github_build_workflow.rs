//! Guards the GitHub Actions build, `.github/workflows/build.yml` (card #539):
//! every push to a branch checks the commit and builds its three images, and
//! only once every check has passed does the release-versions plugin publish
//! them to GHCR under the one version it claimed for the run. Nothing here
//! deploys; the deploys are Woodpecker's (`pipeline_prod_gating.rs`). Also
//! guards the `docker/` files the image builds use.

mod support;

use std::collections::BTreeSet;

use serde_yaml::Value;
use support::{Build, build, pipeline};

/// The release-versions plugin as a digest-pinned container action.
const RELEASE_VERSIONS: &str =
    "docker://ghcr.io/vcheesbrough/woodpecker-plugin-release-versions:0.2.0@sha256:";

/// Each image build job, the Dockerfile it builds, and the image it names.
const IMAGE_BUILDS: [(&str, &str, &str); 3] = [
    (
        "build-server",
        "server",
        "ghcr.io/vcheesbrough/sovereign-config",
    ),
    (
        "build-broker",
        "broker",
        "ghcr.io/vcheesbrough/sovereign-config-woodpecker-broker",
    ),
    (
        "build-cli",
        "cli",
        "ghcr.io/vcheesbrough/sovereign-config-cli",
    ),
];

/// The jobs that check the commit; publish waits for each of them.
const CHECKS: [&str; 4] = [
    "script-validation",
    "web-bundle",
    "unit-test",
    "client-playwright",
];

fn with<'a>(step: &'a Value, name: &str) -> Option<&'a str> {
    step.get("with")
        .and_then(|inputs| inputs.get(name))
        .and_then(Value::as_str)
}

fn permissions(build: &Build, job: &str) -> Option<&'static str> {
    let permissions = build.job(job).get("permissions")?;
    if permissions.get("packages").and_then(Value::as_str) == Some("write") {
        Some("packages")
    } else if permissions.get("contents").and_then(Value::as_str) == Some("write") {
        Some("contents")
    } else {
        None
    }
}

/// A push to any branch, or a manual run, builds — never a tag push (the
/// deploys write tags) and never a pull request, whose code would run with
/// this repository's token.
#[test]
fn the_build_runs_on_branch_pushes_and_manual_runs_only() {
    let build = build();
    let on = build
        .workflow()
        .get("on")
        .and_then(Value::as_mapping)
        .expect("the workflow names its triggers");
    let triggers: BTreeSet<&str> = on.keys().filter_map(Value::as_str).collect();
    assert_eq!(triggers, BTreeSet::from(["push", "workflow_dispatch"]));
    let push = on.get("push").expect("push trigger");
    assert_eq!(
        push.get("branches")
            .and_then(Value::as_sequence)
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        push["branches"][0].as_str(),
        Some("**"),
        "every branch builds"
    );
    assert!(push.get("tags").is_none(), "a tag push is not a build");
    assert_eq!(
        build.workflow()["permissions"]["contents"].as_str(),
        Some("read"),
        "the token is read-only unless a job widens it"
    );
}

/// Nothing in the build deploys: no job runs Compose, applies a blueprint,
/// exercises live Authentik, names a deployed environment or uses a GitHub
/// environment's secrets (card #466; the deploys hold those, on mini).
#[test]
fn the_build_never_deploys() {
    let build = build();
    for job in build.job_names() {
        let text = serde_yaml::to_string(build.job(&job)).expect("job serialises");
        for forbidden in [
            "compose",
            "authentik-blueprint",
            "live_",
            "sovereign-config-dev",
            "sovereign-config-prod",
            "environment:",
            "${{ secrets.",
        ] {
            // The run's own token is the only secret the build reads.
            let text = text.replace("${{ secrets.GITHUB_TOKEN }}", "");
            assert!(
                !text.contains(forbidden),
                "{job} must not deploy ({forbidden})"
            );
        }
    }
}

/// One run, one version: only `version` claims it, with the plugin, and every
/// job that names it reads that job's output. It is the only job that may
/// write to the repository (the claim is a `refs/builds/<version>` ref).
#[test]
fn the_version_is_claimed_once_by_the_plugin() {
    let build = build();
    let claims: Vec<String> = build
        .job_names()
        .into_iter()
        .filter(|job| {
            build
                .uses(job, RELEASE_VERSIONS)
                .iter()
                .any(|step| with(step, "mode") == Some("version"))
        })
        .collect();
    assert_eq!(claims, ["version"]);
    let claim = build.uses("version", RELEASE_VERSIONS)[0];
    assert_eq!(with(claim, "major_minor_source"), Some("cargo"));
    assert_eq!(
        build.job("version")["outputs"]["release_tag"].as_str(),
        Some("${{ steps.version.outputs.release_tag }}")
    );
    for job in build.job_names() {
        let expected = match job.as_str() {
            "version" => Some("contents"),
            "publish" => Some("packages"),
            _ => None,
        };
        assert_eq!(
            permissions(&build, &job),
            expected,
            "{job} has the wrong write permission"
        );
        if job == "version" {
            continue;
        }
        let text = serde_yaml::to_string(build.job(&job)).expect("job serialises");
        if text.contains("RELEASE_TAG") {
            assert_eq!(
                build.job(&job)["env"]["RELEASE_TAG"].as_str(),
                Some("${{ needs.version.outputs.release_tag }}"),
                "{job} must take the version from the version job"
            );
            assert!(build.needs(&job).contains(&"version".to_owned()));
        }
    }
}

/// Nothing is published unless every check passed and all three images were
/// built, and only the plugin pushes: it refuses an image that lacks this
/// version's labels or is already published, before it pushes any.
#[test]
fn publish_waits_for_every_check_and_build() {
    let build = build();
    let needs: BTreeSet<String> = build.needs("publish").into_iter().collect();
    let expected: BTreeSet<String> = build
        .job_names()
        .into_iter()
        .filter(|job| job != "publish")
        .collect();
    assert_eq!(needs, expected, "publish must wait for every other job");
    for job in CHECKS
        .iter()
        .chain(IMAGE_BUILDS.iter().map(|(job, _, _)| job))
    {
        assert!(expected.contains(*job), "{job} should exist");
    }

    let publish = build.uses("publish", RELEASE_VERSIONS);
    assert_eq!(publish.len(), 1);
    assert_eq!(with(publish[0], "mode"), Some("publish"));
    let images: Vec<&str> = with(publish[0], "images")
        .expect("publish lists the images")
        .split(',')
        .collect();
    let release: Vec<&str> = IMAGE_BUILDS.iter().map(|(_, _, image)| *image).collect();
    assert_eq!(
        images, release,
        "publish must push all three images, together"
    );
    assert!(
        build.run_text("publish").contains("docker load"),
        "publish pushes the images the build jobs built"
    );
    for job in build.job_names() {
        let run = build.run_text(&job);
        assert!(
            !run.contains("docker push") && !run.contains("docker login"),
            "{job}: only the plugin pushes, from publish"
        );
    }
}

/// Every action is pinned to a commit, and every container action to a
/// digest, so the build runs what was reviewed.
#[test]
fn every_action_is_pinned() {
    let build = build();
    for job in build.job_names() {
        for step in build.steps(&job) {
            let Some(uses) = step.get("uses").and_then(Value::as_str) else {
                continue;
            };
            let pinned = if let Some(image) = uses.strip_prefix("docker://") {
                image.contains("@sha256:")
            } else {
                uses.rsplit_once('@').is_some_and(|(_, reference)| {
                    reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit())
                })
            };
            assert!(pinned, "{job}: {uses} must be pinned to a commit or digest");
        }
    }
}

/// The checks run in the same digest-pinned Rust image the image builds
/// compile with, so a check and a build never disagree about the toolchain.
#[test]
fn the_checks_build_with_the_dockerfiles_rust_image() {
    let build = build();
    let unit = build.run_text("unit-test");
    let rust: BTreeSet<String> = pinned_digests(&unit, "docker.io/library/rust")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let dockerfiles: BTreeSet<String> = all_dockerfiles()
        .iter()
        .flat_map(|(_, text)| {
            pinned_digests(text, "docker.io/library/rust")
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(rust.len(), 1, "unit-test must run one pinned rust image");
    assert_eq!(rust, dockerfiles);
}

/// The repository root, where the `docker/` build files live.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn dockerfile(image: &str) -> String {
    let path = repo_root().join(format!("docker/{image}.Dockerfile"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()))
}

/// Every `docker/*.Dockerfile`, by file name.
fn all_dockerfiles() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = std::fs::read_dir(repo_root().join("docker"))
        .expect("docker/ should be readable")
        .map(|entry| entry.expect("docker/ entry should be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "Dockerfile")
        })
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).expect("Dockerfile should be readable");
            (name, text)
        })
        .collect();
    files.sort();
    files
}

/// One named build stage of a Dockerfile: its `FROM … AS <name>` line up to the
/// next `FROM`.
///
/// `ARG` is scoped to the stage that declares it, so an assertion against the
/// whole file cannot tell "the server build receives this" from "some other
/// stage does". Only a slice can.
fn stage<'a>(dockerfile: &'a str, name: &str) -> &'a str {
    let header = format!(" AS {name}\n");
    let start = dockerfile
        .find(&header)
        .unwrap_or_else(|| panic!("the Dockerfile should have a stage named {name}"))
        + header.len();
    let rest = &dockerfile[start..];
    match rest.find("\nFROM ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

/// The digest-pinned references to `image@sha256:` in a Dockerfile.
fn pinned_digests<'a>(dockerfile: &'a str, image: &str) -> BTreeSet<&'a str> {
    dockerfile
        .split_whitespace()
        .filter(|word| word.contains(&format!("{image}@sha256:")))
        .collect()
}

/// Each image builds from its own file, which has one final stage, so no build
/// can pick the wrong image by omitting a `--target`.
#[test]
fn each_image_build_uses_its_own_dockerfile() {
    let build = build();
    for (job, image, _) in IMAGE_BUILDS {
        let commands = build.run_text(job);
        let file = format!("-f docker/{image}.Dockerfile ");
        assert!(
            commands.contains("docker build") && commands.contains(&file),
            "{job} must build with {file}"
        );
        assert!(
            !commands.contains("--target"),
            "{job} must not select a stage: its Dockerfile builds one image"
        );
        dockerfile(image);
    }
    assert!(
        !repo_root().join("Dockerfile").exists(),
        "there must be no root Dockerfile for an untargeted `docker build .` to pick up"
    );
}

/// Every flag in an image build command must start a token of its own.
///
/// The build commands are single long shell lines, so an edit that drops one
/// space glues a flag onto the value before it. Docker does not complain about
/// an unknown flag — it takes the merged token as the build context path and
/// fails with a usage error about the argument count, which names neither the
/// flag nor the label that swallowed it. Nothing else here reads the command as
/// tokens, so only this catches it, and it catches it before a run rather than
/// after one.
#[test]
fn image_build_flags_are_never_glued_to_the_value_before_them() {
    let build = build();
    for (job, _, _) in IMAGE_BUILDS {
        let commands = build.run_text(job);
        for (offset, _) in commands.match_indices("--") {
            let preceding = commands[..offset].chars().next_back();
            assert!(
                matches!(preceding, None | Some(' ' | '\n' | '"')),
                "{job}: a flag is glued to the token before it at {:?}",
                &commands[offset.saturating_sub(40)..commands.len().min(offset + 20)]
            );
        }
    }
}

/// Server, broker and CLI ship as one release: the same commit, the same
/// version. Each job builds its image straight to its release name, labelled
/// with the version and commit the plugin checks, and saves exactly that image
/// for publish — it never pushes.
#[test]
fn every_image_is_built_under_its_release_name_and_saved() {
    let build = build();
    for (job, image, published) in IMAGE_BUILDS {
        let commands = build.run_text(job);
        assert!(
            commands.contains(&format!("IMAGE={published}:$RELEASE_TAG\n")),
            "{job} must build {published}"
        );
        assert!(
            commands.contains("--tag \"$IMAGE\"")
                && commands.contains("docker save --output image.tar \"$IMAGE\""),
            "{job} must save exactly the image it built"
        );
        let built_at = commands.find("docker build").expect("builds");
        let saved_at = commands.find("docker save").expect("saves");
        assert!(built_at < saved_at, "{job} saves what it just built");
        assert!(
            commands.contains("org.opencontainers.image.version=\"$RELEASE_TAG\"")
                && commands.contains("org.opencontainers.image.revision=\"$GITHUB_SHA\"")
                && commands.contains("--build-arg RELEASE_VERSION=\"$RELEASE_TAG\""),
            "{job} must label its image with the version and commit"
        );
        assert!(
            commands.contains(
                "org.opencontainers.image.source=https://github.com/vcheesbrough/sovereign-config"
            ),
            "{job}: the source label links the GHCR package to the repository"
        );
        let uploads = build.uses(job, "actions/upload-artifact@");
        assert_eq!(uploads.len(), 1);
        assert_eq!(
            with(uploads[0], "name"),
            Some(format!("image-{image}").as_str())
        );
        assert_eq!(with(uploads[0], "path"), Some("image.tar"));
    }
}

/// The revision reaches the binary only if all four links hold: CI passes the
/// commit as a build arg, the **server** stage declares that arg, that stage
/// exports it to `cargo build`, and `build.rs` reads it into the compiled
/// binary.
///
/// A broken link degrades silently to `revision="unknown"` — the same value a
/// local build reports — so nothing fails and no unit test can tell the two
/// apart. The chain is only visible to someone scraping a deployment.
///
/// The `ARG` assertion is scoped to the `builder` stage on purpose: Docker
/// scopes `ARG` per stage, so an `ARG REVISION` sitting in `installer-builder`
/// would satisfy a file-wide search while the server binary got nothing.
#[test]
fn the_server_image_is_stamped_with_the_commit_it_was_built_from() {
    let commands = build().run_text("build-server");
    assert!(
        commands.contains("--build-arg REVISION=\"$GITHUB_SHA\""),
        "the build must pass the commit to the image"
    );

    let server_dockerfile = dockerfile("server");
    let builder = stage(&server_dockerfile, "builder");
    assert!(
        builder.contains("ARG REVISION"),
        "the stage that builds the server must declare the arg it is passed"
    );
    assert!(
        builder.contains("SOVEREIGN_CONFIG_REVISION=\"$REVISION\""),
        "the stage must export the arg to cargo, or build.rs never sees it"
    );

    let build_script =
        std::fs::read_to_string(repo_root().join("crates/sovereign-config-server/build.rs"))
            .expect("build.rs should be readable");
    assert!(
        build_script.contains("SOVEREIGN_CONFIG_REVISION"),
        "build.rs must read the variable the image build exports"
    );
}

/// The builder stages are duplicated across the files, not shared, so their
/// base images must not drift apart.
#[test]
fn every_dockerfile_pins_the_same_base_images() {
    let files = all_dockerfiles();
    assert!(
        files.len() >= 4,
        "expected web/server/broker/cli Dockerfiles, found {files:?}"
    );
    for image in [
        "docker.io/library/rust",
        "docker.io/library/debian",
        "docker:27-cli",
        "docker/dockerfile:1.7",
    ] {
        let digests: BTreeSet<&str> = files
            .iter()
            .flat_map(|(_, text)| pinned_digests(text, image))
            .collect();
        assert!(
            digests.len() <= 1,
            "every docker/*.Dockerfile must pin {image} to one digest, found {digests:?}"
        );
    }
    for (name, text) in &files {
        assert_eq!(
            pinned_digests(text, "docker.io/library/rust").len(),
            1,
            "{name} must build from the pinned rust image"
        );
        let mut stages: Vec<&str> = Vec::new();
        for from in text.lines().filter(|line| line.starts_with("FROM ")) {
            let words: Vec<&str> = from
                .split_whitespace()
                .filter(|word| !word.starts_with("--"))
                .collect();
            let base = words.get(1).copied().unwrap_or_default();
            assert!(
                base == "scratch" || base.contains("@sha256:") || stages.contains(&base),
                "{name}: {from} must pin its base image by digest or build on an earlier stage"
            );
            if let Some(stage) = words
                .iter()
                .position(|word| word.eq_ignore_ascii_case("AS"))
                .and_then(|index| words.get(index + 1))
            {
                stages.push(stage);
            }
        }
    }
}

/// The broker and CLI never ship the web bundle, and the broker never ships
/// the server, so neither build pays for them.
#[test]
fn broker_and_cli_builds_compile_only_what_they_ship() {
    for image in ["broker", "cli"] {
        let text = dockerfile(image);
        assert!(
            !text.contains("trunk") && !text.contains("wasm32") && !text.contains("web-dist"),
            "docker/{image}.Dockerfile must not build the web bundle"
        );
        assert!(
            !text.contains("--package sovereign-config-server"),
            "docker/{image}.Dockerfile must not compile the server"
        );
    }
    assert!(
        dockerfile("broker").contains("--package sovereign-config-woodpecker-broker"),
        "the broker Dockerfile must compile the broker"
    );
    assert!(
        dockerfile("cli").contains("--package sovereign-config-cli"),
        "the CLI Dockerfile must compile the CLI"
    );
}

/// `web-dist/` is not in the checkout (card #278), so the checks build the
/// release bundle into it from `docker/web.Dockerfile` — the stages the server
/// image builds it with — before anything that embeds or serves it runs; and no
/// image build copies a `web-dist` from the build context, where a stale or
/// debug bundle could stand in for the one the build makes.
#[test]
fn the_checks_build_the_web_bundle_the_server_embeds() {
    let build = build();
    let bundle = build.run_text("web-bundle");
    assert!(
        bundle.contains("docker build -f docker/web.Dockerfile")
            && bundle.contains("--output type=local,dest=web-dist "),
        "web-bundle must export docker/web.Dockerfile's bundle into web-dist: {bundle}"
    );
    // build.rs reads the bundle's hidden .trunk-profile marker, which an
    // artifact leaves out unless asked.
    let upload = build.uses("web-bundle", "actions/upload-artifact@");
    assert_eq!(upload.len(), 1);
    assert_eq!(
        upload[0]["with"]["include-hidden-files"].as_bool(),
        Some(true),
        "the uploaded bundle must keep its .trunk-profile marker"
    );
    for job in ["unit-test", "client-playwright"] {
        assert_eq!(
            build.needs(job),
            ["web-bundle"],
            "{job} must wait for web-bundle"
        );
        let download = build.uses(job, "actions/download-artifact@");
        assert_eq!(download.len(), 1);
        assert_eq!(with(download[0], "name"), Some("web-dist"));
        assert_eq!(with(download[0], "path"), Some("web-dist"));
    }
    let playwright = build.run_text("client-playwright");
    assert!(
        !playwright.contains("docker build"),
        "client-playwright must test the bundle web-bundle built, not build its own"
    );
    assert!(
        playwright.contains("docker cp web-dist/."),
        "client-playwright must serve the bundle web-bundle built"
    );

    for (name, text) in all_dockerfiles() {
        assert!(
            !text.lines().any(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                words.first() == Some(&"COPY")
                    && !words.iter().any(|word| word.starts_with("--from="))
                    && words
                        .iter()
                        .any(|word| word.trim_start_matches("./").starts_with("web-dist"))
            }),
            "{name} must build the web bundle, never COPY web-dist from the build context"
        );
    }
    for image in ["server", "web"] {
        assert!(
            stage(&dockerfile(image), "web-builder")
                .contains("trunk build --release --dist ../../web-dist"),
            "docker/{image}.Dockerfile must build the release bundle into web-dist explicitly"
        );
    }
}

/// The CLI image is the exact docker CLI image the deploys' own docker steps
/// run, plus the static CLI binary on `PATH` — so another repository's step can
/// swap its image for it and gain `sovereign-config` without losing `docker`.
#[test]
fn the_cli_image_is_the_pipeline_docker_image_plus_the_cli() {
    let dockerfile = dockerfile("cli");
    let stage = dockerfile
        .split("\nFROM ")
        .find(|stage| {
            stage
                .lines()
                .next()
                .is_some_and(|from| from.ends_with(" AS cli-runtime"))
        })
        .expect("docker/cli.Dockerfile must define a cli-runtime stage");
    assert!(
        dockerfile.trim_end().ends_with(stage.trim_end()),
        "cli-runtime must be the final stage, so the untargeted build produces it"
    );
    let base = stage
        .split_whitespace()
        .next()
        .expect("cli-runtime needs a base image");
    let pipeline = pipeline();
    let build_image = pipeline
        .step_in("deploy-dev", "deploy-dev")
        .get("image")
        .and_then(Value::as_str)
        .expect("deploy-dev needs an image");
    assert!(
        base.starts_with("docker:27-cli@sha256:") && base == build_image,
        "cli-runtime must be based on the digest-pinned docker CLI image the pipeline uses, got {base}"
    );
    assert!(
        stage.contains("COPY --from=builder /tmp/sovereign-config /usr/local/bin/sovereign-config"),
        "cli-runtime must carry the static musl CLI"
    );
    assert!(
        dockerfile.contains("--target x86_64-unknown-linux-musl"),
        "the CLI must be built as a static musl binary"
    );
    // build-server strips and packages the same musl path in the shared target
    // cache, possibly at the same time, so the CLI image builds elsewhere.
    assert!(
        dockerfile.contains("--target-dir /src/target/cli-image")
            && dockerfile.contains(
                "/src/target/cli-image/x86_64-unknown-linux-musl/release/sovereign-config"
            ),
        "the CLI image must build into its own target directory, not the server's musl output"
    );
    assert!(
        !stage.contains("ENTRYPOINT") && !stage.contains("\nUSER "),
        "cli-runtime keeps the base image's entrypoint and user so pipeline commands can drive Docker"
    );
    assert!(
        stage.contains("sovereign-config --version") && stage.contains("$RELEASE_VERSION"),
        "cli-runtime must gate on the binary reporting the release it was built for"
    );
}
