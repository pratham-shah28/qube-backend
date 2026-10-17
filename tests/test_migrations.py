import subprocess
import sys


def test_migrations_match_models(tmp_path):
    """`alembic upgrade head` builds the schema and leaves nothing for autogenerate to add."""
    env = {
        "QUBE_DB_URL": f"sqlite:///{tmp_path / 'm.db'}",
        "QUBE_JWT_SECRET": "x",
        "QUBE_MASTER_KEY": "00" * 16,
        "PATH": "",
    }
    for args in (["upgrade", "head"], ["check"], ["downgrade", "base"]):
        r = subprocess.run(
            [sys.executable, "-m", "alembic", *args], env=env, capture_output=True, text=True
        )
        assert r.returncode == 0, r.stderr
