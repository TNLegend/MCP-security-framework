"""Read-only local pipeline identity check; no signing prerequisites.

Optionally compare the current installed source with a previous manifest.
Hashes are diagnostic evidence only, not an ADMIN tool approval.
"""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'backend'),str(ROOT)]
from app.services.tda_application.pipeline import configured_pipeline, check_revision_transition

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--previous-manifest',type=Path)
    args=parser.parse_args();pipeline=configured_pipeline()
    if args.previous_manifest:
        previous=json.loads(args.previous_manifest.read_text(encoding='utf8'))
        check_revision_transition(previous,pipeline._manifest)
    print(json.dumps({'pipeline_identity':pipeline.identity,'analyzer_revision':pipeline._manifest['execution']['analyzer_revision'],
        'sources':len(pipeline._manifest['execution']['source_sha256']),'result':'LOCAL_SHA256_CHECKED'},sort_keys=True))
    return 0

if __name__=='__main__':sys.exit(main())
