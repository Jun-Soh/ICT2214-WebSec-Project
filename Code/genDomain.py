import sys
import io
import homoglyphs as hg
import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim
from PIL import Image, ImageDraw, ImageFont


sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


class Domain:
    def __init__(self, domain_name, font_path="arial.ttf", image_size=(300, 100), font_size=48):
        """
        Initialize the Domain class with the domain name and rendering settings.

        Args:
            domain_name (str): The domain name.
            font_path (str): Path to the font file.
            image_size (tuple): Size of the output image (width, height).
            font_size (int): Font size for the text.
        """
        self.domain_name = domain_name
        self.font_path = font_path
        self.image_size = image_size
        self.font_size = font_size
        self.homoglyph_versions = dict()

        # Render the original domain name as an image
        self.original_image = self.render_text_as_image(domain_name)

    def render_text_as_image(self, text):
        """
        Render a given text into an image.

        Args:
            text (str): Text to render.

        Returns:
            np.array: Image of the rendered text as a NumPy array.
        """
        # Create a blank white image
        img = Image.new("RGB", self.image_size, "white")
        draw = ImageDraw.Draw(img)

        # Load the font
        try:
            font = ImageFont.truetype(self.font_path, self.font_size)
        except:
            raise Exception(f"Font file not found: {self.font_path}")

        # Get text bounding box and calculate center position
        # (left, top, right, bottom)
        text_bbox = draw.textbbox((0, 0), text, font=font)
        text_width = text_bbox[2] - text_bbox[0]
        text_height = text_bbox[3] - text_bbox[1]
        position = ((self.image_size[0] - text_width) //
                    2, (self.image_size[1] - text_height) // 2)

        # Draw the text
        draw.text(position, text, fill="black", font=font)

        # Convert the PIL image to a NumPy array
        return np.array(img)

    def compare_images(self, homoglyph_image):
        """
        Compare two images using Structural Similarity Index (SSIM).

        Args:
            image1 (np.array): First image as a NumPy array.
            image2 (np.array): Second image as a NumPy array.

        Returns:
            float: Similarity score (1.0 = identical, 0.0 = completely different).
        """
        # Convert images to grayscale
        gray1 = cv2.cvtColor(self.original_image, cv2.COLOR_RGB2GRAY)
        gray2 = cv2.cvtColor(homoglyph_image, cv2.COLOR_RGB2GRAY)

        # Compute SSIM between the two images
        score, _ = ssim(gray1, gray2, full=True)
        return score

    def generate_homoglyph(self):
        """
        Generate a homoglyph version of the domain, ensuring no duplicates.

        Returns:
            str: A unique homoglyph version of the domain.
        """
        stop_index = self.domain_name.find(".") # returns -1 if not found which is fine
        if stop_index == -1:
            stop_index = len(self.domain_name)
        
        for i in range(stop_index):
            char_to_replace = self.domain_name[i]
            homoglyphs_list = hg.Homoglyphs().get_combinations(char_to_replace)

            if homoglyphs_list:
                new_domains = [self.domain_name[:i] + homoglyph_char +
                               self.domain_name[i + 1:] for homoglyph_char in homoglyphs_list]

                for new_domain in new_domains:
                    if new_domain not in self.homoglyph_versions and new_domain != self.domain_name:
                        self.homoglyph_versions[new_domain] = self.compare_images(
                            self.render_text_as_image(new_domain))

    def get_top_homoglyphs(self, n=10):
        """
        Get the top n homoglyph versions based on similarity score.
        """
        sorted_homoglyphs = sorted(
            self.homoglyph_versions.items(), key=lambda x: x[1], reverse=True)
        return sorted_homoglyphs[:n]


def genDomain(domain_name):
    domain = Domain(domain_name)
    domain.generate_homoglyph()

    # print(len(domain.homoglyph_versions),
    #       "unique homoglyph versions generated.")

    top_homoglyphs = domain.get_top_homoglyphs(n=10)
    return top_homoglyphs
