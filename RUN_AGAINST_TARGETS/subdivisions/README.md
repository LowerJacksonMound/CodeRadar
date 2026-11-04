# subdivisions

A small, dependency-free parcel registry for a fictional neighbourhood. It keeps
lots, owners and zoning rules in a SQLite database, imports and exports CSV, audits
parcels against the zoning rules, and prints plain-text reports.

## Quick start

```
PYTHONPATH=src python3 -m subdivisions
```

With no arguments the command seeds an in-memory database with sample data, runs the
registry report and prints it. Other subcommands:

```
subdivisions demo                      # same as running with no arguments
subdivisions report --db registry.db   # report on a persistent database
subdivisions audit --db registry.db    # zoning compliance findings
subdivisions export-csv parcels.csv    # write the sample parcels to CSV
subdivisions import-csv parcels.csv --db registry.db
```

## Layout

- `src/subdivisions/models.py` - `Parcel`, `Owner` and the `Zone` enum
- `src/subdivisions/zoning.py` - zoning rules per zone
- `src/subdivisions/audit.py` - compliance checks
- `src/subdivisions/store.py` - SQLite persistence
- `src/subdivisions/registry.py` - service layer over the store
- `src/subdivisions/csvio.py` - CSV import and export
- `src/subdivisions/report.py` / `render.py` - report model and text rendering
- `src/subdivisions/seed.py` - sample data
- `src/subdivisions/cli.py` - command-line entry point

## Tests

```
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The tests are plain `unittest` cases and also run under `pytest`.

## License

MIT, see `LICENSE`.
