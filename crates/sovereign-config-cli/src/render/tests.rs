use super::variable_name;

// The name is the leaf, exactly as stored. `/foo/AbC` holding `bAr` reaches
// the command as `AbC=bAr`, the same as `export AbC=bAr` would — which is the
// one rule a deploy can predict without knowing this code exists.
#[test]
fn a_leaf_name_is_the_variable_name_exactly_as_stored() {
    for leaf in [
        "AbC",
        "github_token",
        "DATABASE_URL",
        "MixedCase_2",
        "_internal",
        "lowercase",
    ] {
        assert_eq!(variable_name(leaf).unwrap(), leaf);
    }
}

// Paths have been case-retentive since 2.18.0, so four spellings of one name
// are four distinct variables here. Uppercasing would collapse them and, worse,
// leave `AbC` unreachable: no path would produce it.
#[test]
fn spellings_that_differ_only_in_case_stay_distinct() {
    let spellings = ["myvalue", "MyValue", "MYVALUE", "myVALUE"];
    let mut rendered: Vec<&str> = spellings
        .iter()
        .map(|leaf| variable_name(leaf).unwrap())
        .collect();
    assert_eq!(rendered, spellings);
    rendered.sort_unstable();
    rendered.dedup();
    assert_eq!(rendered.len(), spellings.len(), "two spellings collapsed");
}

// Path segments and variable names do not have the same grammar: `-` is legal
// in a path and cannot be referenced in a shell or a compose file. Exporting
// `DB-PASSWORD` would satisfy `execve` and then fail at the point of use, with
// nothing to show for it — exactly the silent-missing-configuration failure
// `render` exists to remove — so it is refused before the command runs.
#[test]
fn a_leaf_that_cannot_be_a_variable_name_is_refused_not_mangled() {
    for refused in ["db-password", "DB-Password", "2fa_key", "2FA_KEY", "", "0"] {
        assert!(
            variable_name(refused).is_err(),
            "accepted {refused:?} as a variable name"
        );
    }
}

// Folding `-` to `_` is the tempting fix and the wrong one: it is many-to-one,
// so two distinct values would race for one variable. The refusal above keeps
// the mapping injective, which this asserts from the other side — nothing maps
// onto a name another leaf could also produce.
#[test]
fn the_mapping_is_injective_over_accepted_names() {
    for accepted in ["db_password", "dbpassword", "db_password_1"] {
        assert_eq!(variable_name(accepted).unwrap(), accepted);
    }
    // The name a fold would have collided with is not reachable at all.
    assert!(variable_name("db-password").is_err());
}

// The refusal has to say which leaf, or an operator cannot act on it. Paths
// are not secret; values are, and none is available at this point anyway.
#[test]
fn the_refusal_names_the_offending_leaf() {
    let error = variable_name("db-password").unwrap_err().to_string();
    assert!(error.contains("db-password"), "unhelpful error: {error}");
}
