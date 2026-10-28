import time
import torch
from torchvision.models import resnet50, ResNet50_Weights


def main():
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)

    weights = ResNet50_Weights.DEFAULT
    model = resnet50(weights=weights)
    model.eval()

    transform = weights.transforms()

    # Fixed input: avoids filesystem/network activity during benchmarking.
    image = torch.rand(3, 224, 224)
    input_tensor = transform(image).unsqueeze(0)

    # Warmup
    with torch.inference_mode():
        for _ in range(100):
            model(input_tensor)

    start_time = time.perf_counter_ns()

    # Run continuously
    with torch.inference_mode():
        while True:
            inference_start = time.perf_counter_ns()

            model(input_tensor)

            inference_end = time.perf_counter_ns()

            elapsed_ms = (inference_end - start_time) / 1_000_000
            latency_ns = inference_end - inference_start
            timestamp = time.time()

            # Approximate cycles assuming a 5.40 GHz CPU.
            # Change this if your CPU frequency is different.
            cycles = latency_ns * 5.40

            print(
                f"timestamp = {timestamp:.9f}, "
                f"elapsed time = {elapsed_ms:.0f} ms, "
                f"measured latency = {latency_ns / 1000:.2f}us "
                f"(~{cycles:.1f} cycles)",
                flush=True
            )
            # sleep for 100ms 
            time.sleep(0.1)


if __name__ == "__main__":
    main()
