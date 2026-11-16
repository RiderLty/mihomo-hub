#!/usr/bin/env python
"""本地启动入口：python run.py"""
from __future__ import annotations

import uvicorn

from app.config import HOST, PORT


def main() -> None:
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False, log_level="info")


if __name__ == "__main__":
    main()
