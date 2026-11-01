# Tripwire

Tripwire reviews untrusted code by running it. A model served by Vultr Serverless Inference writes a pytest probe for a change, the probe and the repo's tests run inside a locked-down container on a Vultr VM, and the report comes from the executed output, not from reading the diff.

Status: work in progress for the Vultr Agent Rush Hackathon (challenge "Blast Radius Zero", pattern A, sandboxed code execution). This README only states what the code does today; measured results will be added after the lab has been run on the Vultr VM.

## What it does

1. **Plan.** The model reads the submitted files and the stated claim, then returns the claims it will check and a pytest file that checks them.
2. **Execute.** The files plus the probe are streamed into a fresh container over stdin. Nothing from the host is mounted, and no credentials are present.
3. **Self-heal.** If the probe fails, the model decides whether the probe or the code is at fault. A broken probe is rewritten and retried (at most two retries). A code fault is never "healed" into a pass.
4. **Verdict.** The model gives `safe_to_merge`, `needs_changes` or `unsafe`, citing the executed output. A deterministic floor can only make the verdict worse: if the sandbox observed a network connection or a read of a sensitive path, the verdict is raised to `unsafe` regardless of what the model said.
5. **Receipt.** Every report lists the guards that were active, whether the container was destroyed, and the attempts the in-sandbox audit hook saw.

## Containment

| Guard | Flag |
|---|---|
| Process isolation, no host data | no mounts, files arrive over stdin into a tmpfs |
| Network | `--network none` |
| Read-only root filesystem | `--read-only` |
| Capabilities | `--cap-drop ALL --security-opt no-new-privileges` |
| Non-root user | `--user 65534:65534` |
| Process limit | `--pids-limit 64` |
| Memory and CPU | `--memory 128m --memory-swap 128m --cpus 0.5` |
| Wall clock | 8 s, then `docker rm -f` |
| Lifecycle | `--rm` plus an explicit remove and an existence check after every run |
| Secret hygiene | the inference key lives only in the control plane process; the sandbox environment is empty |

The Python audit hook inside the sandbox (`tripwire/runtime/sitecustomize.py`) is observability. Hostile code can try to disable it, so its output is reported as attempts that were seen, never as proof that nothing else happened. The boundary is the container.

## Containment lab

`tripwire/lab.py` runs eight hostile payloads (key exfiltration, `rm -rf` of a data directory, planting files outside scratch space, phoning home, an infinite loop, a process storm, a memory bomb, a root probe) under three kinds of policy: an unguarded decoy container, the full policy, and the full policy with exactly one guard removed. Each result is labelled `observed` (measured by the lab host: canary listener hits, bait files, exit codes, wall time) or `self-reported` (printed by the payload). When a guard is removed, limits relax to lab ceilings instead of disappearing, so the demo cannot hurt the host; the unguarded decoy is still a disposable container.

## Vultr services used

- **Vultr Cloud Compute VM** hosts the FastAPI control plane and the Docker sandboxes.
- **Vultr Serverless Inference** (`https://api.vultrinference.com/v1`, OpenAI-compatible) serves every model call in `tripwire/llm.py`. Model ids come from the public `/v1/models` list.

## Run it

```bash
docker build -t tripwire-sandbox:latest -f deploy/sandbox.Dockerfile .
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
export VULTR_INFERENCE_API_KEY=...   # never commit this
export TRIPWIRE_MODEL=<model id from /v1/models>
.venv/bin/uvicorn tripwire.server:app --port 8000
```

Tests: `pytest` runs the policy, agent (mocked model) and lab-scoring tests without Docker. On a host with Docker and the sandbox image, `pytest -m docker` also runs the real eight-payload matrix. `TRIPWIRE_TEST_SERVER=1 pytest tests/test_server.py` exercises the HTTP layer.

## Limits

- Python projects with pytest or the standard library only. The sandbox has no network, so dependencies cannot be installed.
- Public demo requests are rate limited and size limited.
- A container is a weaker boundary than a microVM. gVisor (`runtime="runsc"`) is supported by the policy but is not enabled unless the host has it installed.

## License

MIT
