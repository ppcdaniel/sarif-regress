#!/usr/bin/env python3
"""Render the README terminal animation from real SarifRegress summary output."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Sequence

from PIL import Image, ImageDraw, ImageFont

CANVAS_WIDTH: Final = 1_200
CANVAS_HEIGHT: Final = 720
WINDOW_MARGIN: Final = 28
TITLE_BAR_HEIGHT: Final = 56
CONTENT_LEFT: Final = 58
CONTENT_TOP: Final = 104
LINE_HEIGHT: Final = 27
FONT_SIZE: Final = 21
MAX_SUMMARY_LINES: Final = 8
MAX_SUMMARY_LINE_CHARACTERS: Final = 100
FINAL_FRAME_DURATION_MILLISECONDS: Final = 5_000

BACKGROUND_COLOR: Final = "#0d1117"
WINDOW_COLOR: Final = "#161b22"
BORDER_COLOR: Final = "#30363d"
PRIMARY_TEXT_COLOR: Final = "#e6edf3"
MUTED_TEXT_COLOR: Final = "#8b949e"
PROMPT_COLOR: Final = "#3fb950"
ACCENT_COLOR: Final = "#58a6ff"
MOVED_COLOR: Final = "#d29922"
TITLE_COLOR: Final = "#c9d1d9"

REGULAR_FONT_CANDIDATES: Final = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
)
BOLD_FONT_CANDIDATES: Final = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
)


@dataclass(frozen=True, slots=True)
class TerminalLine:
    """One terminal line and its semantic display role."""

    text: str
    color: str = PRIMARY_TEXT_COLOR
    bold: bool = False


@dataclass(frozen=True, slots=True)
class AnimationStage:
    """A cumulative terminal state and how long it remains visible."""

    visible_line_count: int
    duration_milliseconds: int


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for the deterministic renderer."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary-file",
        required=True,
        type=Path,
        help="UTF-8 lines produced by demo-summary.jq.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Destination GIF path.",
    )
    return parser.parse_args()


def load_font(candidates: Sequence[str], size: int) -> ImageFont.FreeTypeFont:
    """Load the first available deterministic DejaVu Mono font."""

    for candidate in candidates:
        font_path = Path(candidate)
        if font_path.is_file():
            return ImageFont.truetype(str(font_path), size=size)

    joined_candidates = ", ".join(candidates)
    raise FileNotFoundError(
        f"DejaVu Sans Mono is required; checked: {joined_candidates}"
    )


def read_summary_lines(summary_path: Path) -> tuple[str, ...]:
    """Read bounded summary text generated from the stable JSON report."""

    raw_text = summary_path.read_text(encoding="utf-8")
    summary_lines = tuple(raw_text.splitlines())
    if not summary_lines:
        raise ValueError("The demo summary is empty.")
    if len(summary_lines) > MAX_SUMMARY_LINES:
        raise ValueError(
            f"The demo summary has {len(summary_lines)} lines; "
            f"the limit is {MAX_SUMMARY_LINES}."
        )

    oversized_lines = [
        line for line in summary_lines if len(line) > MAX_SUMMARY_LINE_CHARACTERS
    ]
    if oversized_lines:
        raise ValueError(
            "A demo summary line exceeds "
            f"{MAX_SUMMARY_LINE_CHARACTERS} characters."
        )

    return summary_lines


def build_terminal_lines(summary_lines: Sequence[str]) -> tuple[TerminalLine, ...]:
    """Build the exact command transcript shown in the README animation."""

    command_lines = (
        TerminalLine("$ sarif-regress compare \\", PROMPT_COLOR),
        TerminalLine("    --baseline baseline.sarif \\", MUTED_TEXT_COLOR),
        TerminalLine("    --candidate candidate.sarif \\", MUTED_TEXT_COLOR),
        TerminalLine("    --json-out report.json \\", MUTED_TEXT_COLOR),
        TerminalLine(
            "    --html-out report.html 2>diagnostics.txt", MUTED_TEXT_COLOR
        ),
        TerminalLine("$ echo $?", PROMPT_COLOR),
        TerminalLine("0", ACCENT_COLOR, bold=True),
        TerminalLine("$ jq -r -f demo-summary.jq report.json", PROMPT_COLOR),
    )
    rendered_summary = tuple(
        TerminalLine(
            line,
            MOVED_COLOR if line.startswith("MOVED") else PRIMARY_TEXT_COLOR,
            bold=line.startswith("MOVED"),
        )
        for line in summary_lines
    )
    return command_lines + rendered_summary


def build_animation_stages(total_line_count: int) -> tuple[AnimationStage, ...]:
    """Create cumulative reveal stages ending in a long readable frame."""

    candidate_stages = (
        AnimationStage(5, 1_700),
        AnimationStage(7, 900),
        AnimationStage(8, 900),
        AnimationStage(9, 1_200),
        AnimationStage(10, 1_200),
        AnimationStage(total_line_count, FINAL_FRAME_DURATION_MILLISECONDS),
    )
    return tuple(
        stage
        for stage in candidate_stages
        if stage.visible_line_count <= total_line_count
    )


def draw_window_chrome(
    draw: ImageDraw.ImageDraw,
    bold_font: ImageFont.FreeTypeFont,
) -> None:
    """Draw the fixed terminal window frame and title bar."""

    window_bounds = (
        WINDOW_MARGIN,
        WINDOW_MARGIN,
        CANVAS_WIDTH - WINDOW_MARGIN,
        CANVAS_HEIGHT - WINDOW_MARGIN,
    )
    draw.rounded_rectangle(
        window_bounds,
        radius=14,
        fill=WINDOW_COLOR,
        outline=BORDER_COLOR,
        width=2,
    )
    title_bar_bottom = WINDOW_MARGIN + TITLE_BAR_HEIGHT
    draw.line(
        (
            WINDOW_MARGIN,
            title_bar_bottom,
            CANVAS_WIDTH - WINDOW_MARGIN,
            title_bar_bottom,
        ),
        fill=BORDER_COLOR,
        width=2,
    )

    for center_x, color in (
        (52, "#ff5f56"),
        (76, "#ffbd2e"),
        (100, "#27c93f"),
    ):
        draw.ellipse((center_x - 7, 49, center_x + 7, 63), fill=color)

    title = "sarif-regress — real ESLint SARIF"
    title_bounds = draw.textbbox((0, 0), title, font=bold_font)
    title_width = title_bounds[2] - title_bounds[0]
    draw.text(
        ((CANVAS_WIDTH - title_width) / 2, 44),
        title,
        font=bold_font,
        fill=TITLE_COLOR,
    )


def render_frame(
    lines: Sequence[TerminalLine],
    visible_line_count: int,
    regular_font: ImageFont.FreeTypeFont,
    bold_font: ImageFont.FreeTypeFont,
) -> Image.Image:
    """Render one cumulative animation frame."""

    frame = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), BACKGROUND_COLOR)
    draw = ImageDraw.Draw(frame)
    draw_window_chrome(draw, bold_font)

    for line_index, terminal_line in enumerate(lines[:visible_line_count]):
        font = bold_font if terminal_line.bold else regular_font
        draw.text(
            (CONTENT_LEFT, CONTENT_TOP + (line_index * LINE_HEIGHT)),
            terminal_line.text,
            font=font,
            fill=terminal_line.color,
        )

    return frame


def save_animation(
    frames: Sequence[Image.Image],
    durations: Sequence[int],
    output_path: Path,
) -> None:
    """Quantize and save a compact deterministic animated GIF."""

    if not frames or len(frames) != len(durations):
        raise ValueError("Animation frames and durations must be non-empty and aligned.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    quantized_frames = tuple(
        frame.quantize(
            colors=128,
            method=Image.Quantize.MEDIANCUT,
            dither=Image.Dither.NONE,
        )
        for frame in frames
    )
    quantized_frames[0].save(
        output_path,
        save_all=True,
        append_images=list(quantized_frames[1:]),
        duration=list(durations),
        loop=0,
        optimize=True,
        disposal=1,
    )


def main() -> int:
    """Render the terminal animation and fail loudly on invalid source data."""

    arguments = parse_arguments()
    summary_lines = read_summary_lines(arguments.summary_file)
    terminal_lines = build_terminal_lines(summary_lines)
    stages = build_animation_stages(len(terminal_lines))
    regular_font = load_font(REGULAR_FONT_CANDIDATES, FONT_SIZE)
    bold_font = load_font(BOLD_FONT_CANDIDATES, FONT_SIZE)

    frames = tuple(
        render_frame(
            terminal_lines,
            stage.visible_line_count,
            regular_font,
            bold_font,
        )
        for stage in stages
    )
    durations = tuple(stage.duration_milliseconds for stage in stages)
    save_animation(frames, durations, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
