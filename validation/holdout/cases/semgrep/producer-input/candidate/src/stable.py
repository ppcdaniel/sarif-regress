def exact_cases() -> None:
    # HOLDOUT:semgrep-exact-01
    holdout_sink("SEMGREP_EXACT_01")
    # HOLDOUT:semgrep-exact-02
    holdout_sink("SEMGREP_EXACT_02")
    # HOLDOUT:semgrep-exact-03
    holdout_sink("SEMGREP_EXACT_03")
    # HOLDOUT:semgrep-exact-04
    holdout_sink("SEMGREP_EXACT_04")
    # HOLDOUT:semgrep-exact-05
    holdout_sink("SEMGREP_EXACT_05")


def message_cases() -> None:
    # HOLDOUT:semgrep-message-modified-01
    holdout_sink("SEMGREP_MESSAGE_01")
    # HOLDOUT:semgrep-message-modified-02
    holdout_sink("SEMGREP_MESSAGE_02")
    # HOLDOUT:semgrep-message-modified-03
    holdout_sink("SEMGREP_MESSAGE_03")
    # HOLDOUT:semgrep-message-modified-04
    holdout_sink("SEMGREP_MESSAGE_04")
    # HOLDOUT:semgrep-message-modified-05
    holdout_sink("SEMGREP_MESSAGE_05")


def neutral_padding() -> tuple[str, str, str]:
    return ("alpha", "beta", "gamma")


def moved_cases() -> None:
    # HOLDOUT:semgrep-moved-01
    holdout_sink("SEMGREP_MOVED_01")
    # HOLDOUT:semgrep-moved-02
    holdout_sink("SEMGREP_MOVED_02")
    # HOLDOUT:semgrep-moved-03
    holdout_sink("SEMGREP_MOVED_03")
    # HOLDOUT:semgrep-moved-04
    holdout_sink("SEMGREP_MOVED_04")
    # HOLDOUT:semgrep-moved-05
    holdout_sink("SEMGREP_MOVED_05")


def line_shift_cases() -> None:
    # Controlled insertion above the first finding.
    # HOLDOUT:semgrep-line-shift-01
    holdout_sink("SEMGREP_SHIFT_01")
    # Controlled insertion A above the second finding.
    # Controlled insertion B above the second finding.
    # HOLDOUT:semgrep-line-shift-02
    holdout_sink("SEMGREP_SHIFT_02")
    # Controlled insertion A above the third finding.
    # Controlled insertion B above the third finding.
    # Controlled insertion C above the third finding.
    # HOLDOUT:semgrep-line-shift-03
    holdout_sink("SEMGREP_SHIFT_03")
    # Controlled insertion A above the fourth finding.
    # Controlled insertion B above the fourth finding.
    # Controlled insertion C above the fourth finding.
    # Controlled insertion D above the fourth finding.
    # HOLDOUT:semgrep-line-shift-04
    holdout_sink("SEMGREP_SHIFT_04")
    # Controlled insertion A above the fifth finding.
    # Controlled insertion B above the fifth finding.
    # Controlled insertion C above the fifth finding.
    # Controlled insertion D above the fifth finding.
    # Controlled insertion E above the fifth finding.
    # HOLDOUT:semgrep-line-shift-05
    holdout_sink("SEMGREP_SHIFT_05")
