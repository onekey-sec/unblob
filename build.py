from mypyc.build import mypycify

def build(setup_kwargs):
    ext_modules=mypycify([
        'unblob/math.py',
    ])

    setup_kwargs.update(
        {
            "ext_modules": ext_modules,
            "zip_safe": False,  # Extension modules are not ZIP-safe by desing
        }
    )
