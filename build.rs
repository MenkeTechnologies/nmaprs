fn main() {
    cc::Build::new()
        .cpp(true)
        .file("c/expr_match.cpp")
        .opt_level(3)
        .warnings(false)
        .compile("nmap_expr_match");
}
