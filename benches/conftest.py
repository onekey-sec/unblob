def pytest_benchmark_scale_unit(config, unit, benchmarks, best, worst, sort):
    prefix = ""
    scale = 1.0

    if unit == "operations":
        prefix = "MiB/s "
        for benchmark in benchmarks:
            input_file = benchmark["params"].get("input_file")
            if not input_file:
                continue
            input_size = input_file.stat().st_size
            scale_factor = input_size / 1024 / 1024
            benchmark["ops"] *= scale_factor
            benchmark["scaled"] = True

    return prefix, scale
