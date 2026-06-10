import os

import cairosvg
import svgwrite


def create_sigma_rangeproof_svg(svg_file="sigma_rangeproof_icon.svg"):
    """
    Create the Sigma Rangeproof SVG icon with:
    - Centered Σ
    - 3D gradient shield
    - Thick border around Σ for separation
    """
    size = 200
    dwg = svgwrite.Drawing(svg_file, size=(f"{size}px", f"{size}px"), viewBox=f"0 0 {size} {size}")

    # Define gradient for shield
    gradient = dwg.linearGradient(start=("0%", "0%"), end=("0%", "100%"), id="shieldGradient")
    gradient.add_stop_color(offset="0%", color="#33F5D2")  # Light teal top
    gradient.add_stop_color(offset="100%", color="#007F6E")  # Dark teal bottom
    dwg.defs.add(gradient)

    # Background circle
    dwg.add(dwg.circle(center=("100", "100"), r="95",
                       fill="#1E1E2E", stroke="#00D1B2", stroke_width=5))

    # Shield with gradient fill
    shield_path = "M100 20 L160 50 L150 140 L100 180 L50 140 L40 50 Z"
    dwg.add(dwg.path(d=shield_path, fill="url(#shieldGradient)",
                     stroke="#00D1B2", stroke_width=4))

    # Sigma symbol with thick border
    sigma_text = "Σ"
    center_x, center_y = "100", "100"

    # Border layer (stroke only)
    dwg.add(dwg.text(sigma_text,
                     insert=(center_x, center_y),
                     text_anchor="middle",
                     dominant_baseline="middle",
                     font_size="90",
                     font_family="DejaVu Sans Mono, monospace",
                     fill="none",
                     stroke="#1E1E2E",  # Dark border color
                     stroke_width=8,
                     stroke_linejoin="round"))

    # Fill layer (main Σ color)
    dwg.add(dwg.text(sigma_text,
                     insert=(center_x, center_y),
                     text_anchor="middle",
                     dominant_baseline="middle",
                     font_size="90",
                     font_family="DejaVu Sans Mono, monospace",
                     fill="#00D1B2"))

    dwg.save()
    print(f"✅ SVG saved to {svg_file}")


def svg_to_png(svg_file, png_file, size):
    """
    Convert an SVG file to PNG format.
    """
    if not os.path.exists(svg_file):
        raise FileNotFoundError(f"SVG file '{svg_file}' not found.")

    cairosvg.svg2png(url=svg_file, write_to=png_file,
                     output_width=size, output_height=size)
    print(f"✅ PNG saved to {png_file} ({size}x{size}px)")


if __name__ == "__main__":
    svg_filename = "sigma_rangeproof_icon.svg"

    # Step 1: Create SVG
    create_sigma_rangeproof_svg(svg_filename)

    # Step 2: Export PNGs in multiple sizes
    sizes = {
        "sigma_rangeproof_icon.png": 512,   # Large
        "sigma_rangeproof_icon_128.png": 128, # Medium
        "favicon.png": 32                   # Small favicon
    }

    for filename, size in sizes.items():
        svg_to_png(svg_filename, filename, size)

    # Keep the docs-site copies in sync so the logo never drifts from the source.
    docs_assets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "assets")
    if os.path.isdir(docs_assets):
        import shutil

        shutil.copy(svg_filename, os.path.join(docs_assets, "sigma-rangeproof.svg"))
        shutil.copy("favicon.png", os.path.join(docs_assets, "favicon.png"))
        shutil.copy("sigma_rangeproof_icon_128.png",
                    os.path.join(docs_assets, "sigma-rangeproof-128.png"))
        print(f"✅ synced logo, favicon, and 128px icon into {docs_assets}")
