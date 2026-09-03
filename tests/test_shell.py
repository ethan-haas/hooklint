"""Acceptance gate 5: shell parsing is real parsing. Every case here would
pass under a naive regex ("flag if a line contains $") but a real tokenizer
must get the quote-state-dependent answer right in each direction."""
from hooklint.shell import find_expansions, split_pipeline, tokenize_argv, basename_lower


def _unsafe(cmd):
    return [e for e in find_expansions(cmd) if not e.safe]


def _safe(cmd):
    return [e for e in find_expansions(cmd) if e.safe]


def test_single_quoted_var_is_safe():
    assert _unsafe("echo '$FOO'") == []
    assert len(_safe("echo '$FOO'")) == 1


def test_unquoted_var_is_flagged():
    unsafe = _unsafe("echo $FOO")
    assert len(unsafe) == 1
    assert unsafe[0].text == "$FOO"


def test_double_quoted_var_is_flagged():
    # SPEC: decided by tokenization -- an expansion in a word that is NOT
    # single-quoted is flagged, including double-quoted.
    unsafe = _unsafe('echo "$FOO"')
    assert len(unsafe) == 1


def test_braced_param_expansion():
    assert _unsafe("echo ${FOO}") != []
    assert _unsafe("echo '${FOO}'") == []


def test_nested_quotes_double_containing_single():
    # a literal single quote inside a double-quoted word has no special
    # meaning; the $FOO is still inside DOUBLE state -> flagged
    cmd = 'echo "it'"'"'s $FOO"'
    unsafe = _unsafe(cmd)
    assert len(unsafe) == 1


def test_nested_quotes_single_containing_double():
    # a literal double quote inside a single-quoted word has no special
    # meaning; the $FOO stays inside SINGLE state -> safe
    cmd = "echo 'say \"hi\" $FOO'"
    assert _unsafe(cmd) == []
    assert len(_safe(cmd)) == 1


def test_command_substitution_dollar_paren_unquoted_flagged():
    unsafe = _unsafe("echo $(cat /etc/hostname)")
    assert any(e.kind == "cmdsub" for e in unsafe)


def test_command_substitution_dollar_paren_single_quoted_safe():
    # a real shell does NOT expand $(...) inside single quotes at all --
    # the whole thing including $( is a literal string. hooklint must not
    # flag it.
    assert _unsafe("echo '$(cat /etc/hostname)'") == []


def test_command_substitution_nested_var_inside_is_also_scanned():
    unsafe = _unsafe("echo $(echo $INNER)")
    kinds = {e.kind for e in unsafe}
    assert "cmdsub" in kinds
    assert "var" in kinds


def test_backtick_substitution_unquoted_flagged():
    unsafe = _unsafe("echo `whoami`")
    assert any(e.kind == "backtick" for e in unsafe)


def test_backtick_substitution_single_quoted_safe():
    assert _unsafe("echo '`whoami`'") == []


def test_escaped_dollar_is_literal_not_expansion():
    assert find_expansions(r"echo \$FOO") == []
    assert find_expansions(r'echo "\$FOO"') == []


def test_escaped_dollar_mixed_with_real_expansion():
    cmd = r'echo "\$FOO $BAR"'
    results = find_expansions(cmd)
    assert len(results) == 1
    assert results[0].text == "$BAR"
    assert not results[0].safe


def test_heredoc_quoted_delimiter_body_is_literal():
    cmd = "cat <<'EOF'\n$SECRET is not expanded here\nEOF\n"
    assert find_expansions(cmd) == []


def test_heredoc_unquoted_delimiter_body_is_expanded():
    cmd = "cat <<EOF\n$SECRET is expanded here\nEOF\n"
    unsafe = _unsafe(cmd)
    assert len(unsafe) == 1
    assert unsafe[0].text == "$SECRET"


def test_heredoc_double_quoted_delimiter_is_also_literal():
    cmd = 'cat <<"EOF"\n$SECRET\nEOF\n'
    assert find_expansions(cmd) == []


def test_special_positional_and_at_params():
    unsafe = _unsafe("echo $1 $@ $#")
    kinds = [e.kind for e in unsafe]
    assert kinds.count("special") == 3


def test_mixed_word_partial_single_quote():
    # `--path=$HOME/'x'` -- $HOME is unquoted (flagged), the trailing 'x'
    # segment is single-quoted but contains no expansion
    cmd = "echo --path=$HOME/'literal'"
    unsafe = _unsafe(cmd)
    assert len(unsafe) == 1
    assert unsafe[0].text == "$HOME"


# -- pipeline / argv (rule 6 plumbing) -----------------------------------

def test_split_pipeline_basic():
    assert split_pipeline("curl -sL url | bash") == ["curl -sL url", "bash"]


def test_split_pipeline_ignores_pipe_inside_quotes():
    segs = split_pipeline("echo 'a | b' | cat")
    assert segs == ["echo 'a | b'", "cat"]


def test_split_pipeline_ignores_or_operator():
    assert split_pipeline("cmd1 || cmd2") == ["cmd1 || cmd2"]


def test_split_pipeline_ignores_pipe_inside_cmdsub():
    segs = split_pipeline("echo $(a | b)")
    assert segs == ["echo $(a | b)"]


def test_tokenize_argv_strips_quotes():
    assert tokenize_argv("curl -sL 'https://x/y'") == ["curl", "-sL", "https://x/y"]


def test_basename_lower():
    assert basename_lower("/usr/bin/CURL") == "curl"
    assert basename_lower("bash") == "bash"
    assert basename_lower("C:\\Tools\\PowerShell.exe") == "powershell.exe"
