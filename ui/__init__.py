"""Presentation layer for the PhishGuard-HDV Streamlit UI.

Modules:
    status.py      - map backend outputs to the new user-facing statuses
    styles.py      - one global light-theme CSS block
    components.py  - reusable HTML/Streamlit components

This package contains NO detection logic, no ML, no threat-intel calls and no
database code. It only renders what the backend already produced.
"""
