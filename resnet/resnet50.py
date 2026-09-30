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

    # Run continuously
    with torch.inference_mode():
        while True:
            model(input_tensor)


if __name__ == "__main__":
    main()
