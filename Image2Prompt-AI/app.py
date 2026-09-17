import streamlit as st
from PIL import Image
from transformers import BlipProcessor, BlipForConditionalGeneration
import torch
import numpy as np
from collections import Counter
from pathlib import Path


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Image2Prompt",
    page_icon="🖼️",
    layout="centered"
)


# ============================================================
# TITLE
# ============================================================

st.title("🖼️ Image2Prompt")

st.subheader(
    "Deep Learning-Based Automatic Prompt Generation"
)

st.write(
    "Upload an image and the deep learning model "
    "will analyze it and generate a detailed AI prompt."
)


# ============================================================
# LOAD BLIP MODEL
# ============================================================

@st.cache_resource
def load_model():

    processor = BlipProcessor.from_pretrained(
        "Salesforce/blip-image-captioning-base"
    )

    model = BlipForConditionalGeneration.from_pretrained(
        "Salesforce/blip-image-captioning-base"
    )

    device = "cuda" if torch.cuda.is_available() else "cpu"

    model.to(device)
    model.eval()

    return processor, model, device


# ============================================================
# LOAD MODEL
# ============================================================

with st.spinner("Loading deep learning model..."):

    processor, model, device = load_model()


# ============================================================
# DEVICE INFORMATION
# ============================================================

if device == "cuda":

    st.success("🚀 GPU acceleration enabled")

else:

    st.info("💻 Running on CPU")


# ============================================================
# IMAGE UPLOAD
# ============================================================

uploaded_file = st.file_uploader(
    "📤 Upload an image",
    type=[
        "jpg",
        "jpeg",
        "png",
        "webp"
    ]
)


# ============================================================
# IMAGE ANALYSIS FUNCTIONS
# ============================================================

def generate_caption(image):

    """
    Generate a strong visual description using BLIP.
    Multiple descriptions are generated using different prompts
    and combined into the final prompt.
    """

    prompts = [
        "a detailed photograph of",
        "a detailed image showing",
        "a realistic photograph showing",
        "a complete visual description of"
    ]

    captions = []

    for prompt in prompts:

        inputs = processor(
            images=image,
            text=prompt,
            return_tensors="pt"
        )

        inputs = {
            key: value.to(device)
            for key, value in inputs.items()
        }

        with torch.no_grad():

            output = model.generate(
                **inputs,
                max_new_tokens=70,
                num_beams=5,
                repetition_penalty=1.2,
                length_penalty=1.0
            )

        caption = processor.decode(
            output[0],
            skip_special_tokens=True
        )

        caption = caption.strip()

        if caption:

            captions.append(caption)

    # Remove duplicate descriptions

    unique_captions = []

    for caption in captions:

        if caption.lower() not in [
            x.lower() for x in unique_captions
        ]:

            unique_captions.append(caption)

    if unique_captions:

        return unique_captions[0]

    return "A visually detailed scene."


# ============================================================
# COLOR ANALYSIS
# ============================================================

def get_dominant_colors(image, number_of_colors=6):

    image = image.convert("RGB")

    # Resize for faster processing

    small_image = image.resize((100, 100))

    pixels = np.array(
        small_image
    ).reshape(-1, 3)

    # Reduce color precision

    pixels = (pixels // 32) * 32

    counter = Counter(
        map(tuple, pixels)
    )

    common_colors = counter.most_common(
        number_of_colors
    )

    names = []

    for rgb, count in common_colors:

        r, g, b = rgb

        brightness = (
            0.299 * r +
            0.587 * g +
            0.114 * b
        )

        saturation = (
            max(r, g, b) -
            min(r, g, b)
        )

        # Color classification

        if brightness < 45:

            name = "deep black"

        elif brightness > 225 and saturation < 30:

            name = "white"

        elif saturation < 25:

            if brightness < 100:
                name = "dark gray"
            elif brightness < 180:
                name = "gray"
            else:
                name = "light gray"

        elif r > 150 and g < 100 and b < 100:

            name = "red"

        elif r > 150 and g > 100 and b < 90:

            name = "warm yellow"

        elif r > 130 and g > 70 and b < 80:

            name = "orange"

        elif g > r * 1.25 and g > b * 1.15:

            name = "green"

        elif b > r * 1.25 and b > g * 1.05:

            name = "blue"

        elif r > 120 and b > 100 and g < 100:

            name = "purple"

        elif r > 140 and b > 130 and g > 80:

            name = "pink"

        elif r > 100 and g > 70 and b < 80:

            name = "brown"

        else:

            name = "mixed natural tones"

        names.append(name)

    # Remove duplicates

    final_names = []

    for name in names:

        if name not in final_names:

            final_names.append(name)

    return final_names[:5]


# ============================================================
# IMAGE GEOMETRY ANALYSIS
# ============================================================

def analyze_image_geometry(image):

    width, height = image.size

    aspect_ratio = width / height

    if aspect_ratio > 1.7:

        orientation = "wide landscape orientation"

    elif aspect_ratio > 1.15:

        orientation = "landscape orientation"

    elif aspect_ratio < 0.6:

        orientation = "tall portrait orientation"

    elif aspect_ratio < 0.85:

        orientation = "portrait orientation"

    else:

        orientation = "balanced near-square orientation"

    return width, height, orientation


# ============================================================
# BRIGHTNESS ANALYSIS
# ============================================================

def analyze_lighting(image):

    gray = image.convert("L")

    pixels = np.array(gray)

    brightness = float(
        pixels.mean()
    )

    contrast = float(
        pixels.std()
    )

    if brightness < 65:

        light_description = (
            "a predominantly dark and low-key lighting appearance"
        )

    elif brightness < 115:

        light_description = (
            "moderate lighting with relatively subdued brightness"
        )

    elif brightness < 175:

        light_description = (
            "balanced natural-looking illumination"
        )

    else:

        light_description = (
            "bright illumination with a high overall exposure"
        )

    if contrast < 30:

        contrast_description = (
            "soft overall tonal contrast"
        )

    elif contrast < 60:

        contrast_description = (
            "moderate tonal contrast"
        )

    else:

        contrast_description = (
            "strong tonal contrast between darker and brighter areas"
        )

    return (
        light_description +
        " and " +
        contrast_description
    )


# ============================================================
# SUBJECT POSITION ESTIMATION
# ============================================================

def estimate_composition(image):

    """
    Uses image brightness distribution to provide a basic
    composition description. This is intentionally conservative
    so unsupported details are not invented.
    """

    gray = np.array(
        image.convert("L").resize((30, 30))
    )

    height, width = gray.shape

    left = gray[:, :width // 3].mean()
    center = gray[
        :,
        width // 3:2 * width // 3
    ].mean()
    right = gray[:, 2 * width // 3:].mean()

    top = gray[:height // 3, :].mean()
    middle = gray[
        height // 3:2 * height // 3,
        :
    ].mean()
    bottom = gray[2 * height // 3:, :].mean()

    horizontal_values = {
        "left": left,
        "center": center,
        "right": right
    }

    vertical_values = {
        "upper": top,
        "middle": middle,
        "lower": bottom
    }

    horizontal = min(
        horizontal_values,
        key=horizontal_values.get
    )

    vertical = min(
        vertical_values,
        key=vertical_values.get
    )

    return horizontal, vertical


# ============================================================
# CLEAN TEXT
# ============================================================

def clean_caption(text):

    text = text.strip()

    unwanted = [
        "a detailed photograph of",
        "a detailed image showing",
        "a realistic photograph showing",
        "a complete visual description of"
    ]

    lower_text = text.lower()

    for phrase in unwanted:

        if lower_text.startswith(
            phrase
        ):

            text = text[
                len(phrase):
            ].strip()

    if text:

        text = text[0].upper() + text[1:]

    return text


# ============================================================
# A-Z PROMPT GENERATOR
# ============================================================

def generate_detailed_prompt(
    caption,
    colors,
    lighting,
    orientation,
    width,
    height,
    horizontal,
    vertical
):

    caption = clean_caption(
        caption
    )

    color_text = ", ".join(
        colors[:5]
    )

    # --------------------------------------------------------
    # ONE SINGLE PARAGRAPH
    # --------------------------------------------------------

    prompt = (

        "Create a highly accurate visual recreation of "
        "the reference image. "

        "Preserve the primary subject and every clearly "
        "visible characteristic of the subject without "
        "changing the subject's identity, proportions, "
        "overall shape or natural appearance. "

        f"The reference image visually depicts {caption}. "

        "The main subject, its visible appearance, facial "
        "features when visible, hairstyle when visible, "
        "skin appearance when visible, body proportions, "
        "clothing, accessories and other clearly visible "
        "details should be preserved faithfully. "

        "Preserve the subject's visible pose, body position, "
        "gesture, orientation, expression, gaze direction "
        "and apparent action exactly as supported by the "
        "reference image. "

        "Maintain all clearly visible objects and their "
        "relative spatial relationships, including objects "
        "near the subject, behind the subject, beside the "
        "subject and in the surrounding environment. "

        "Preserve the background, walls, floor, furniture, "
        "architecture, landscape or other environmental "
        "elements that are actually visible in the reference. "

        f"The overall visible color palette contains "
        f"{color_text}. "

        f"The image has {lighting}. "

        f"The reference uses {orientation} with an image "
        f"resolution of approximately {width} by {height} "
        "pixels. "

        f"The visual arrangement appears to place the main "
        f"visual information toward the {horizontal} and "
        f"{vertical} region of the frame, while maintaining "
        "the original spatial arrangement. "

        "Preserve the original framing, subject scale, "
        "foreground, middle ground and background "
        "relationships wherever visible. "

        "Maintain the original perspective and viewpoint "
        "as closely as the reference supports. "

        "Preserve visible depth, distance between objects, "
        "overlapping elements and relative object sizes. "

        "Maintain the original lighting direction when it "
        "is visually apparent, together with highlights, "
        "shadows, reflections, brightness variation and "
        "ambient illumination visible in the reference. "

        "Preserve realistic textures such as skin, hair, "
        "fabric, surfaces, walls, objects and environmental "
        "materials whenever those textures are visible. "

        "Keep natural edges, fine details, local contrast "
        "and realistic surface appearance. "

        "Do not add new people, objects, accessories, "
        "clothing, buildings, scenery, colors, emotions, "
        "actions or environmental elements that are not "
        "supported by the reference image. "

        "Do not remove important visible elements. "

        "Do not unnecessarily change the person's pose, "
        "facial expression, hairstyle, clothing or body "
        "position. "

        "Do not convert the image into an unrelated artistic "
        "style. "

        "Keep the visual style consistent with the original "
        "reference, whether it appears photographic, "
        "illustrative, cinematic, casual or otherwise. "

        "Preserve realistic proportions and natural "
        "geometry. "

        "Maintain accurate foreground-to-background "
        "relationships, balanced composition and the "
        "original visual hierarchy. "

        "The final result should remain faithful to the "
        "reference image from subject and appearance through "
        "pose, action, objects, environment, background, "
        "composition, perspective, lighting, colors, "
        "textures, shadows and overall visual structure. "

        "Prioritize visual accuracy over imagination and "
        "include only details that are visible or strongly "
        "supported by the reference image."
    )

    return prompt


# ============================================================
# IMAGE PROCESSING
# ============================================================

if uploaded_file is not None:

    image = Image.open(
        uploaded_file
    ).convert("RGB")

    # --------------------------------------------------------
    # DISPLAY IMAGE
    # --------------------------------------------------------

    st.image(
        image,
        caption="Uploaded Image",
        use_container_width=True
    )

    # --------------------------------------------------------
    # GENERATE BUTTON
    # --------------------------------------------------------

    if st.button(
        "✨ Generate Prompt",
        use_container_width=True
    ):

        with st.spinner(
            "Analyzing image using deep learning..."
        ):

            # ================================================
            # BLIP CAPTION
            # ================================================

            caption = generate_caption(
                image
            )

            # ================================================
            # IMAGE ANALYSIS
            # ================================================

            colors = get_dominant_colors(
                image
            )

            width, height, orientation = (
                analyze_image_geometry(
                    image
                )
            )

            lighting = analyze_lighting(
                image
            )

            horizontal, vertical = (
                estimate_composition(
                    image
                )
            )

            # ================================================
            # A-Z PROMPT
            # ================================================

            detailed_prompt = (
                generate_detailed_prompt(
                    caption=caption,
                    colors=colors,
                    lighting=lighting,
                    orientation=orientation,
                    width=width,
                    height=height,
                    horizontal=horizontal,
                    vertical=vertical
                )
            )

        # ====================================================
        # SUCCESS
        # ====================================================

        st.success(
            "✅ Image analyzed successfully!"
        )

        # ====================================================
        # IMAGE UNDERSTANDING
        # ====================================================

        st.subheader(
            "🔍 Image Understanding"
        )

        st.write(
            caption
        )

        # ====================================================
        # BASIC VISUAL INFORMATION
        # ====================================================

        st.subheader(
            "🧠 Visual Information"
        )

        st.write(
            f"**Image Size:** {width} × {height} pixels"
        )

        st.write(
            f"**Orientation:** {orientation}"
        )

        st.write(
            f"**Dominant Colors:** "
            f"{', '.join(colors)}"
        )

        st.write(
            f"**Lighting:** {lighting}"
        )

        # ====================================================
        # GENERATED PROMPT
        # ====================================================

        st.subheader(
            "🎯 Generated AI Prompt"
        )

        st.text_area(
            "Copy your generated A-Z prompt:",
            detailed_prompt,
            height=500
        )

        # ====================================================
        # SAVE OUTPUT
        # ====================================================

        output_dir = Path(
            "outputs"
        )

        output_dir.mkdir(
            exist_ok=True
        )

        output_file = (
            output_dir /
            "generated_prompt.txt"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "IMAGE2PROMPT AI\n"
            )

            file.write(
                "=" * 70
                + "\n\n"
            )

            file.write(
                "IMAGE DESCRIPTION\n"
            )

            file.write(
                "-" * 70
                + "\n"
            )

            file.write(
                caption
                + "\n\n"
            )

            file.write(
                "GENERATED A-Z PROMPT\n"
            )

            file.write(
                "-" * 70
                + "\n"
            )

            file.write(
                detailed_prompt
            )

        # ====================================================
        # DOWNLOAD
        # ====================================================

        st.download_button(
            label="📥 Download Prompt",
            data=detailed_prompt,
            file_name="generated_prompt.txt",
            mime="text/plain",
            use_container_width=True
        )

        st.success(
            "📁 Prompt saved to outputs/generated_prompt.txt"
        )


# ============================================================
# INFORMATION
# ============================================================

st.divider()

st.caption(
    "Image2Prompt uses the pretrained BLIP "
    "vision-language deep learning model for "
    "image understanding and combines its visual "
    "description with conservative image analysis "
    "to generate a detailed A-Z reconstruction prompt."
)