# Brand assets

The sigma-rangeproof mark: a teal Σ on a shield, on a dark disc.

| File | What it is |
| --- | --- |
| `generate_sigma_rangeproof_icon.py` | The generator. Draws the SVG, then rasterizes it to PNGs. |
| `sigma_rangeproof_icon.svg` | Vector source of truth (200×200). |
| `sigma_rangeproof_icon.png` | 512×512 raster (high-res / social). |
| `sigma_rangeproof_icon_128.png` | 128×128 raster (README / inline). |
| `favicon.png` | 32×32 favicon. |

Palette: disc `#1E1E2E`, ring/Σ `#00D1B2`, shield gradient `#33F5D2` → `#007F6E`.

## Where the docs site reads them

MkDocs can only serve files under `docs/`, so the two files the site embeds are
kept as copies in [`../docs/assets/`](../docs/assets/):

- `sigma-rangeproof.svg`   → `theme.logo` and the docs landing-page hero
- `favicon.png`            → `theme.favicon`
- `sigma-rangeproof-128.png` → the README image

## Regenerating

The generator needs `svgwrite` and `cairosvg` (and `cairosvg` needs the system
Cairo library, e.g. `brew install cairo` or `apt-get install libcairo2`):

```bash
pip install svgwrite cairosvg
cd logo && python generate_sigma_rangeproof_icon.py
```

It rewrites the files here and re-syncs the copies under `docs/assets/`, so the
docs site and README stay in step. Only the rendered assets are committed; the
docs build itself does **not** run the generator (no Cairo needed in CI).
