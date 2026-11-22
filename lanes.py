"""Two-lane dispatch: one delegated subagent per lane, chosen by the route.

The invariant this module enforces: every artifact run ends in a LANE, not a
label. A judge score and a pure function pick the lane; the model never picks
its own.

    route "local"    -> local subagent profile   (desens-local)
    route "frontier" -> frontier subagent profile(desens-frontier)
    route "unrouted" -> no lane; the caller must stop

Falling back from frontier to local when the frontier lane is missing is the one
behaviour that must never happen. It turns a routing decision into a false
claim, and it is why a run could say `route: frontier` while a 4B did the work.
Here that case raises ``FrontierUnconfigured``; the caller records
FRONTIER_UNCONFIGURED and reports no artifact.

Config:

    "lanes": {
      "local":    {"backend": "hermes-subagent", "profile": "desens-local"},
      "frontier": {"backend": "hermes-subagent", "profile": "desens-frontier"}
    }

A legacy ``generator`` block remains the local default so existing configs keep
working; an explicit lane entry wins.
"""
import os

import backends as B

LANES = ("local", "frontier")
_PROFILE_ROOT = os.path.expanduser("~/.hermes/profiles")


class FrontierUnconfigured(Exception):
    """The route chose frontier but no frontier lane exists. Never fall back."""


def lane_for_route(route):
    """Map a pipeline route to a lane, or None. No guessing."""
    return {"local": "local", "frontier": "frontier"}.get(route)


def profile_exists(name):
    return bool(name) and os.path.isdir(os.path.join(_PROFILE_ROOT, str(name)))


class LaneDispatcher:
    """Build and call one generator per lane, lazily, with no cross-lane fallback."""

    def __init__(self, cfg, build=None):
        cfg = cfg or {}
        lanes = cfg.get("lanes") or {}
        legacy = cfg.get("generator") or {}
        self.specs = {
            "local": lanes.get("local") or legacy or None,
            "frontier": lanes.get("frontier") or None,
        }
        self._build = build or B.build_generator
        self._gen = {}

    # -- introspection -------------------------------------------------------
    def spec(self, lane):
        if lane not in LANES:
            raise ValueError(f"unknown lane {lane!r}; lanes are {LANES}")
        return self.specs.get(lane)

    def available(self, lane):
        spec = self.spec(lane)
        if not spec:
            return False
        profile = spec.get("profile")
        if spec.get("backend", "hermes-profile") in ("hermes-profile", "hermes-subagent"):
            return profile_exists(profile)
        return True

    def unavailable_reason(self, lane):
        if self.spec(lane) is None:
            return f"no {lane} lane configured"
        profile = (self.spec(lane) or {}).get("profile")
        if profile and not profile_exists(profile):
            return f"profile {profile!r} does not exist"
        return "lane configured but not usable"

    def backend_name(self, lane):
        return (self.spec(lane) or {}).get("backend", "not configured")

    def profile_name(self, lane):
        return (self.spec(lane) or {}).get("profile")

    def describe(self):
        return {lane: {"available": self.available(lane),
                       "backend": self.backend_name(lane),
                       "profile": self.profile_name(lane)}
                for lane in LANES}

    # -- building ------------------------------------------------------------
    def get(self, lane):
        if lane not in LANES:
            raise ValueError(f"unknown lane {lane!r}; lanes are {LANES}")
        if not self.available(lane):
            if lane == "frontier":
                raise FrontierUnconfigured(self.unavailable_reason(lane))
            raise RuntimeError(f"local lane unavailable: {self.unavailable_reason(lane)}")
        if lane not in self._gen:
            self._gen[lane] = self._build(self.spec(lane))
        return self._gen[lane]

    # -- contract ------------------------------------------------------------
    def generate(self, prompt, workdir=None, max_tokens=None, lane="local"):
        gen = self.get(lane)
        out = gen.generate(prompt, workdir=workdir, max_tokens=max_tokens)
        out["lane"] = lane
        out["backend"] = gen.name
        out["profile"] = self.profile_name(lane)
        return out

    def probe(self, lane="local", timeout=None):
        gen = self.get(lane)
        try:
            p = gen.probe(timeout=timeout) if timeout is not None else gen.probe()
        except TypeError:
            p = gen.probe()
        p = dict(p or {})
        p["lane"] = lane
        p["backend"] = gen.name
        p["profile"] = self.profile_name(lane)
        return p
