def remove_inner_chunks(chunks: List[Chunk]):
    """Remove all chunks from the list which are within another bigger chunks."""
    chunks.sort(key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks[0]]
    for chunk in chunks[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)
    return outer_chunks
