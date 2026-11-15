"""No worker is deployed. Enabling one requires separate T19 OS qualification."""


def submit(*args, **kwargs):
    return {
        "execution": "NOT_RUN",
        "reason": "SIDECAR_DISABLED",
        "authority": "NON_AUTHORITATIVE",
    }
