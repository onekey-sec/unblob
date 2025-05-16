from typing import Union

from .models import HandlerDoc, Reference

_HANDLER_DOC_MARKDOWN_TEMPLATE = """## {name}

!!! {support_info}

    === "Description"

{description}

        ---

        - **Handler type:** {type}
        {vendor}

    === "References"

{references}

{limitations}
"""


def _make_paragraph(lines: Union[str, None, list[str]]):  # noqa: C901
    if not lines:
        return ""

    if not isinstance(lines, list):
        lines = lines.splitlines()

    def _starting_enumeration_needs_newline():
        # Enumerations blocks needs an empty line before and after the blocks
        if not line.startswith("-"):
            return False
        if not formatted_lines:
            return False
        previous_line = formatted_lines[-1].strip()
        return previous_line != "" and not previous_line.startswith("-")

    formatted_lines = []
    for line in [line.strip() for line in lines]:
        if line:
            if _starting_enumeration_needs_newline():
                formatted_lines.append("")
            leading_space_count = 4 if line.startswith("===") else 8
            formatted_lines.append(" " * leading_space_count + line)
        else:
            formatted_lines.append(line)
    return "\n".join(formatted_lines)


def _make_url(*, text: str, link: str) -> str:
    return f'[{text}]({link}){{ target="_blank" }}'


def make_references(references: list[Reference]):
    if not references:
        return ""

    return _make_paragraph(
        [
            *[f"- {_make_url(text=ref.title, link=ref.url)}" for ref in references],
        ]
    )


def make_limitations(limitations: list[str]) -> str:
    if not limitations:
        return ""

    return '    === "Limitations"\n\n' + _make_paragraph(
        [
            *[f"- {limitation}" for limitation in limitations],
        ]
    )


def generate_markdown(doc: HandlerDoc) -> str:
    return _HANDLER_DOC_MARKDOWN_TEMPLATE.format(
        name=doc.name,
        type=doc.handler_type.value,
        vendor=f"- **Vendor:** {doc.vendor}" if doc.vendor is not None else "",
        description=_make_paragraph(doc.description),
        references=make_references(doc.references),
        support_info='success "Fully supported"'
        if doc.fully_supported
        else 'warning "Partially supported"',
        limitations=make_limitations(doc.limitations),
    )
