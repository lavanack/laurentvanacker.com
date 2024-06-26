# Azure AI Services > Computer Vision

Table of content:

- [Azure AI Services \> Computer Vision](#azure-ai-services--computer-vision)
  - [Preliminary Remarks](#preliminary-remarks)
  - [Computer Vision](#computer-vision)
  - [Some examples](#some-examples)

## Preliminary Remarks
All scripts are standalone scripts and will create and use their own related Azure AI Services resources (Free if possible).

***The scripts are not intended to be used in a production environment. The scripts are provided as is without any warranty. The scripts could be used as a starting point for further development.***

## Computer Vision

The [Test-AzComputerVisionImageAnalysis_v3.2.ps1](<Test-AzComputerVisionImageAnalysis_v3.2.ps1>)script downloads 3 random pictures (Resolution: 1920x1080 - Every run will get 3 different pictures) from [https://picsum.photos/](https://picsum.photos/) and use the [Computer Vision > Image Analysis](https://learn.microsoft.com/en-us/azure/cognitive-services/computer-vision/overview-image-analysis?tabs=4-0) of [Azure Cognitive Services](https://learn.microsoft.com/en-us/azure/cognitive-services/) to analyze the downloaded pictures.

For that, it will create a dedicated resource group with a Free (Only one free tier - F0 - per subscription) Computer Vision Cognitive Service (You will have to create your very first Computer Vision resource using the portal to accept the EULA). If you already have set up one, the script will failed and stop (around line 142).

The script will return

- A [photo description](https://learn.microsoft.com/en-us/azure/cognitive-services/computer-vision/concept-describing-images)
- The [detected objets](https://learn.microsoft.com/en-us/azure/cognitive-services/computer-vision/concept-object-detection)  
- The [tags](https://learn.microsoft.com/en-us/azure/cognitive-services/computer-vision/concept-tagging-images) for the recognized objects
- The [image categorization](https://learn.microsoft.com/en-us/azure/cognitive-services/computer-vision/concept-categorizing-images)
- The [detected face(s)](https://learn.microsoft.com/en-us/azure/cognitive-services/computer-vision/concept-detecting-faces) (if applicable)

## Some examples

Judge by yourself with 3 examples ;)
![Alt text](docs/20230713034125_1018-1920x1080.jpg)
![Alt text](docs/20230713034134_877-1920x1080.jpg)
![Alt text](docs/20230713034141_151-1920x1080.jpg)
![Alt text](docs/results.jpg)
