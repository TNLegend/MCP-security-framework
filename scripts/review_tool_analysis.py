import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.db.database import SessionLocal  # noqa: E402
from app.services.tda_application.review_service import ToolReviewService  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Review a tool analysis in the lab.")
    parser.add_argument("action", choices=["approve", "block", "keep_review_required"])
    parser.add_argument("--tool-id", type=int, required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--justification", required=True)
    args = parser.parse_args()

    service = ToolReviewService()
    with SessionLocal() as db:
        if args.action == "approve":
            result = service.approve(
                db=db,
                tool_id=args.tool_id,
                fingerprint=args.fingerprint,
                reviewer=args.reviewer,
                justification=args.justification,
            )
            payload = {"baseline_id": result.id, "fingerprint": result.fingerprint}
        elif args.action == "block":
            result = service.block(
                db=db,
                tool_id=args.tool_id,
                fingerprint=args.fingerprint,
                reviewer=args.reviewer,
                justification=args.justification,
            )
            payload = {"review_id": result.id, "fingerprint": result.fingerprint}
        else:
            result = service.keep_review_required(
                db=db,
                tool_id=args.tool_id,
                fingerprint=args.fingerprint,
                reviewer=args.reviewer,
                justification=args.justification,
            )
            payload = {"review_id": result.id, "fingerprint": result.fingerprint}
        db.commit()

    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
