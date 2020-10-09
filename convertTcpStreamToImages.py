from PIL import Image
from scapy.all import *
import os
import shutil
import extractFileTCP

global fileLen;
numOfImage = 0
global stop
ii = 0
global data
global pl
dirName = 'outputDir/'
path = "outputDir/"

# Creates folder that contains all the extracted images from the TCP raws
def createImagesFolder():
 try:
    #os.remove('rawBytesFile')
    # Create target Directory
    os.mkdir(dirName)
 except FileExistsError:
    # if target Directory exist, it delete the directory and all its containment
    shutil.rmtree(dirName, ignore_errors=True)
    # Then creates target Directory
    os.mkdir(dirName)
    return dirName


def openImage(imageName):
    img = Image.open(imageName)
    img.show()

# create the image file , from raw data bytes array , using startImage and endImage indexes
def createImage(startImageIndex, endImageIndex, numOfImage=None):
    fileName = "image{0}.jpg".format(numOfImage)
    fullpath = os.path.join(path, fileName)

    with open(fullpath, 'wb') as f:
        f.write(data[startImageIndex:endImageIndex])
        if endImageIndex < fileLen:
            numOfImage += 1
            print("create new image")
            findStartOfImage(endImageIndex, numOfImage)


# extract the end of the image index by find the (ffd90d0a) value in raw bytes array relatively to idxStartImage
def findEndOfImage(idxStartImage,numOfImage=None):
    # pl contains all the tcp stream extracted from the pcap file
    ii = idxStartImage
    len = pl.__len__()
    while (ii+3) < len:
           hexVal = hex(pl[ii])
           hexValAfter1 = hex(pl[ii + 2]) #A variable that keeps '0d'
           hexValAfter2 = hex(pl[ii + 3]) #A variable that keeps '0a'
           # check if hexVal variable is 'ff' in Hex
           if hexVal == '0xff':
              nextHexVal = hex(pl[ii + 1])
              # check if nextHexVal variable is 'd9' in Hex
              if nextHexVal == '0xd9':
                  #Check if those variables contain '0a' and '0d'
               if hexValAfter1 == '0xd' and hexValAfter2 == '0xa':
                 idxEndImage=ii
                 createImage(idxStartImage, idxEndImage,numOfImage)
           ii += 1

# extract the end of the image index by find the (0d0affd8) value in raw bytes array relatively to last startIndex
def findStartOfImage(startIndex,numOfImage=None):

    ii = startIndex
    len = pl.__len__()
    while (ii + 3) < len:
        hexVal = hex(pl[ii])
        if ii > 2:
         hexValBefor1 = hex(pl[ii-1])  #A variable that keeps '0a'
         hexValBefor2 = hex(pl[ii-2])  #A variable that keeps '0d'

         # check if hexVal variable is 'ff' in Hex
         if hexVal == '0xff':
             # Check if those variables contain '0a' and '0d'
             if hexValBefor1 == '0xa' and hexValBefor2 == '0xd':
                nextHexVal = hex(pl[ii+1])
                # check if nextHexVal variable is 'd8' in Hex
                if nextHexVal == '0xd8':
                    findEndOfImage(ii,numOfImage)
        ii += 1


if __name__ == '__main__':
  createImagesFolder()
  fname=extractFileTCP.TcpPcapToRawBytesFile()
  with open(fname, 'rb') as f:
    data = f.read()
  # pl contains all the tcp stream extracted from the pcap file
  pl = ([p for p in data])
  file_stats = os.stat(fname)
  fileLen = file_stats.st_size
  print("fileLen = %d",fileLen)
  findStartOfImage(0, numOfImage)
