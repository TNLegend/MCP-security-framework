import app.models  # noqa: F401
from sqlalchemy import text

from app.db.database import Base, engine

PHASE2_INVENTORY_COLUMNS = {
    "mcp_servers": [
        "ADD COLUMN IF NOT EXISTS protocol_version VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS server_info_name VARCHAR(255)",
        "ADD COLUMN IF NOT EXISTS server_info_title VARCHAR(255)",
        "ADD COLUMN IF NOT EXISTS server_info_version VARCHAR(100)",
        "ADD COLUMN IF NOT EXISTS server_info_description TEXT",
        "ADD COLUMN IF NOT EXISTS server_info_icons JSON",
        "ADD COLUMN IF NOT EXISTS server_info_website_url VARCHAR(500)",
        "ADD COLUMN IF NOT EXISTS capabilities JSON",
        "ADD COLUMN IF NOT EXISTS instructions TEXT",
        "ADD COLUMN IF NOT EXISTS transport VARCHAR(100) DEFAULT 'streamable_http' NOT NULL",
        "ADD COLUMN IF NOT EXISTS raw_initialize_result JSON",
        "ADD COLUMN IF NOT EXISTS trust_status VARCHAR(50) DEFAULT 'unknown' NOT NULL",
        "ADD COLUMN IF NOT EXISTS security_status VARCHAR(50) DEFAULT 'not_analyzed' NOT NULL",
        "ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS notes TEXT",
    ],
    "mcp_tools": [
        "ADD COLUMN IF NOT EXISTS title VARCHAR(255)",
        "ADD COLUMN IF NOT EXISTS icons JSON",
        "ADD COLUMN IF NOT EXISTS input_schema JSON",
        "ADD COLUMN IF NOT EXISTS output_schema JSON",
        "ADD COLUMN IF NOT EXISTS annotations JSON",
        "ADD COLUMN IF NOT EXISTS execution JSON",
        "ADD COLUMN IF NOT EXISTS raw_tool_definition JSON",
        "ADD COLUMN IF NOT EXISTS sensitivity VARCHAR(50) DEFAULT 'low' NOT NULL",
        "ADD COLUMN IF NOT EXISTS description_risk_score INTEGER DEFAULT 0 NOT NULL",
        "ADD COLUMN IF NOT EXISTS policy_status VARCHAR(50) DEFAULT 'not_reviewed' NOT NULL",
        "ADD COLUMN IF NOT EXISTS is_sensitive BOOLEAN DEFAULT FALSE NOT NULL",
        "ADD COLUMN IF NOT EXISTS last_analyzed_at TIMESTAMP",
    ],
}


def ensure_phase2_inventory_columns() -> None:
    with engine.begin() as connection:
        for table_name, column_definitions in PHASE2_INVENTORY_COLUMNS.items():
            for column_definition in column_definitions:
                connection.execute(text(f"ALTER TABLE {table_name} {column_definition}"))


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_phase2_inventory_columns()
    print("Database tables created successfully.")


if __name__ == "__main__":
    init_db()
