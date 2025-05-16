set working-directory := ".."

# mkdocs defaults
site-directory := "./site"
dev-address := "localhost:8000"

## Help
help: (_mod_help source_file())

_mod_help justfile:
    @{{ just_executable() }} -f {{ justfile }} --list --unsorted

## Logging
_info message:
    @printf "{{BOLD}}--> {{message}}{{NORMAL}}\n"

_success message="Task finished successfully":
    @printf "{{GREEN}}--> ✔ {{message}}{{NORMAL}}\n"

_error message:
    @printf "{{RED}}--> ✘ {{message}}{{NORMAL}}\n"

# Prints this help

_install_dependencies: (_info "Installing documentation related dependencies") && (_success "Documentation related dependencies are installed")
    uv sync --frozen --all-extras --group docs

# Build documentation to html
build *mkdocs-args: _install_dependencies (_info "Building documentation") && (_success "Documentation built to " + site-directory + " directory")
    uv run mkdocs build -q --site-dir {{ site-directory }} {{ mkdocs-args }}

# Open documentation in browser
open *mkdocs-args: _install_dependencies (_info "Running mkdocs server listening at " + dev-address + ". Press CTRL-C to exit")
    uv run mkdocs serve -q --dev-addr {{ dev-address }} --open {{ mkdocs-args }}

# Generate Handler markdowns
generate-handlers-doc:
    #!/usr/bin/env python
    from pathlib import Path
    from pymdownx import slugs

    from unblob.doc import generate_markdown
    from unblob.handlers import BUILTIN_HANDLERS

    slugifier = slugs.slugify(case="lower", percent_encode=True)
    FORMAT_TABLE_HEADERS = """    | Format        | Type                                 | Fully supported?    |\n    | :------------ | :----------------------------------- | :-----------------: |\n"""

    sorted_handlers = sorted(BUILTIN_HANDLERS, key=lambda handler_class: handler_class.NAME)
    handlers_path = Path("docs/handlers.md")
    print(f"Generating: {handlers_path}")
    with handlers_path.open("w") as f:
        f.write("??? example \"All supported formats\"\n")
        f.write(FORMAT_TABLE_HEADERS)

        for handler_class in sorted_handlers:
            support_icon = "octicons-check-16" if handler_class.DOC.fully_supported else "octicons-alert-fill-12"
            f.write(f"""    | [`{handler_class.DOC.name.upper()}`](#{slugifier(handler_class.DOC.name, sep="-")}) | {handler_class.DOC.handler_type.name} | :{support_icon}: |\n""")

        for handler_class in sorted_handlers:
            content = generate_markdown(handler_class.DOC)
            f.write("\n" + content)
