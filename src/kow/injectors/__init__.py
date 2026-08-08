"""Injector execution machinery (the *how* of substitution).

Policy — the *whether* and *which* — lives in :mod:`kow.policy`.
This package holds the side-effecting executors the addon drives once a
decision is made. Currently: streaming body substitution (:mod:`.body`).
"""
