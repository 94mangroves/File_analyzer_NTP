#
#
# The purpose of this script is to peform a foresic time stamp of files
# This script has been modified to to add the epoch time
# Read about epect time here: https://en.wikipedia.org/wiki/Epoch_(computing) and https://www.foxtonforensics.com/blog/post/timestamps-in-internet-history
# This script will output the following: path - hash value - file size - last modification - last accessed - created - extension - epoch time
# This script will also output a results.txt file and a CSV with the results
# The files must reside in the same folder as the script
# The variables you will need when running this script in Wing IDE is: -d ./_name_of_folder --md5
# Syntax for hashes: 
#                    --md5
#                    --sha1
#                    --sha256
#                    --sha512
#

 
# p-fish : Python File System Hash Program
# Author: C. Hosmer
# Initial Release pFish-py3
# Version 2.0 May 2019 Python 3.x Version
# Version 2.1 July 2019
#    Fixed the omission of hash value from the dump output
#    Added the Future print_functions for Python 2.x

from __future__ import print_function
from contextlib import closing                      # import the closing method from the context library
from socket import socket, AF_INET, SOCK_DGRAM      # import needed methods and attributes from the socket library

import time           # Python Standard Library time functions
import sys            # Python Standard Library system specific parameters
import os             # Python OS or Filesystem Access
import argparse       # Python Standard Library argument parsing
import hashlib        # Python Standard Library for cryptograhic hashing
import struct         # import struct library

''' 
Import Optional PrettyTable Library
to install from the windows command line or linux/mac terminal
pip install prettytable
'''
try:
    from prettytable import PrettyTable
    PRETTY = True
except:
    PRETTY = False
    
# Psuedo Constants

NTP_PACKET_FORMAT = "!12I"    # defines the expected format of the receive packet from pool.ntp.org
NTP_DELTA = 2208988800        # For Windows 1970-01-01 00:00:00 epoch value
NTP_QUERY = b'\x1b'+47*b'\00' # 1b hex followed by 47 00 bytes
    
SECONDS       = 10            # Offsets into the response buffer
MICRO_SECONDS = 11
    
URL      = "pool.ntp.org"     # URL to the Pool of synchronized NTP Servers
PORT     = 123                # NTP Protocol Port Number
    

class FileHasher:

    def __init__(self):
        
        # Psuedo Constants
        
        self.BLOCKSIZE = 2**24     # 1 Megabyte Chunks to Read
        
        ''' process the commandline and establish object attributes '''
        args = self.ParseCommandLine()
        
        self.ROOTPATH   = os.path.abspath(args.rootPath)
        
        if args.md5:
            self.HASHTYPE = 'MD5'
        elif args.sha1:
            self.HASHTYPE = 'SHA1'    
        elif args.sha256:
            self.HASHTYPE = 'SHA256'
        elif args.sha512:
            self.HASHTYPE = 'SHA512'
        else:
            self.HASHTYPE = 'MD5'    
            
        self.resultList   = []
        self.processCount = 0
        self.processSize  = 0
        self.errorCount   = 0        
        
        # resultList field index
        self.FIL_NDX  = 0
        self.HAS_NDX  = 1
        self.SIZ_NDX  = 2
        self.MOD_NDX  = 3
        self.ACC_NDX  = 4
        self.CRE_NDX  = 5
        self.EXT_NDX  = 6
        self.EPH_NDX  = 7
        
        
        self.status = True
        self.details = ''
    
    def ValidateDirectory(self,theDir):
        ''' Validate that this is a legitimate directory '''
    
        # Validate the path is a directory
        if not os.path.isdir(theDir):
            raise argparse.ArgumentTypeError('Directory does not exist')
    
        # Validate the path is readable
        if os.access(theDir, os.R_OK):
            return theDir
        else:
            raise argparse.ArgumentTypeError('Directory is not readable')
    
    def ParseCommandLine(self):
        ''' parse the command line arguments '''
    
        parser = argparse.ArgumentParser('Python File Hashing .. p-fish Python 3.x Version May 2019')
    
        parser.add_argument('-d', '--rootPath', type= self.ValidateDirectory,required=True, help="specify the root path for hashing")
    
        # setup a group where the selection is mutually exclusive and required.
    
        group = parser.add_mutually_exclusive_group(required=True)
        
        group.add_argument('--md5',      help = 'specifies MD5    algorithm',   action='store_true')
        group.add_argument('--sha1',     help = 'specifies SHA1   algorithm',   action='store_true')
        group.add_argument('--sha256',   help = 'specifies SHA256 algorithm',   action='store_true')   
        group.add_argument('--sha512',   help = 'specifies SHA512 algorithm',   action='store_true')   
    
        # create a global object to hold the validated arguments, these will be available then
        # to all the Functions within the _pfish.py module
    
        parsedArguments = parser.parse_args()   
        
        return parsedArguments
            
    #process the file hashes
    
    def InitializeHashObject(self):
        
        if self.HASHTYPE == "MD5":
            obj = hashlib.md5()
        elif self.HASHTYPE == "SHA1":
            obj=hashlib.sha1()                          
        elif self.HASHTYPE == "SHA256":
            obj=hashlib.sha256()
        elif self.HASHTYPE == "SHA512":
            obj=hashlib.sha512()            
        else:
            obj = None
        
        return obj
    
    def ProcessFiles(self):
        
        # Create a loop that process all the files starting
        # at the rootPath, all sub-directories will also be
        # processed
                
        for root, dirs, files in os.walk(self.ROOTPATH):
    
            # for each file obtain the filename and call the HashFile Function
            for nextFile in files:
                fullPath = os.path.join(root, nextFile)
                result = self.HashFile(fullPath)
    
                # if hashing was successful then increment the ProcessCount
                if result is True:
                    self.processCount += 1
                # if not sucessful, the increment the ErrorCount
                else:
                    self.errorCount += 1       
    
    def HashFile(self, theFile):
    
        # Verify that the path is valid
        if os.path.exists(theFile):
    
            #Verify that the path is not a symbolic link
            if not os.path.islink(theFile):
    
                #Verify that the file is real
                if os.path.isfile(theFile):
                    
                    try:
                        with open(theFile, 'rb') as inFile:
                            hashObj = self.InitializeHashObject()
                            if hashObj:
                                while True:
                                    buff = inFile.read(self.BLOCKSIZE)
                                    # if we still have data to process
                                    if buff:
                                        hashObj.update(buff)       
                                    else:
                                        # end of data reached
                                        hashDigest = hashObj.hexdigest().upper()
                                        break
                            else:
                                hashDigest = "INVALID"
                                
                    except Exception as err:
                        #if open fails report the error
                        print('Open Failed: ' + str(err) + theFile)
                        return False
                    
                    theFileStats =  os.stat(theFile)
                    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(theFile)
    
                    # Get the File Size
                    fileSize = size
                    self.processSize = self.processSize + fileSize
                    
                    # Salting 
                    salt = str(fileSize) + str(epoch) + hashDigest
                    hashObj.update(salt.encode('utf-8'))
                    print(salt)
                    
                    # Getting File Extension
                    fileDir = os.path.dirname(theFile)
                    fileBaseName = os.path.basename(theFile)
                    fileName, fileExtension = os.path.splitext(fileBaseName)
                    print(fileDir)
                    print(fileName)
                    print(fileExtension)
    
                    # Convert the MAC Times
                    modifiedTime = time.ctime(mtime)
                    accessTime   = time.ctime(atime)
                    createdTime  = time.ctime(ctime)
                    
                    # Convert the other File Attributes
                    ownerID  = str(uid)
                    groupID  = str(gid)
                    fileMode = bin(mode)    
                    
                    # Add result to resultList
                    self.resultList.append([theFile,hashDigest,fileSize,modifiedTime,accessTime,createdTime,fileExtension,epoch])
                    
                    return True
                
                else:
                    print(theFile, 'Skipped NOT a File')
                    return False
            else:
                print(theFile, 'Skipped Link NOT a File')
                return False
        else:
                print(theFile, 'Path does NOT exist')        
        return False
    
    def DumpResults(self):
        for eachResult in self.resultList:
            print("="*60)
            print("File:          ", eachResult[self.FIL_NDX])
            print("HashType:      ", self.HASHTYPE)
            print("Hash:          ", eachResult[self.HAS_NDX])
            print("Size:          ", '{:,}'.format(eachResult[self.SIZ_NDX]))
            print("Last Modified: ", eachResult[self.MOD_NDX])
            print("Last Accessed: ", eachResult[self.ACC_NDX])
            print("Created:       ", eachResult[self.CRE_NDX])
            print("Extension:     ", eachResult[self.EXT_NDX])
            print("Epoch:         ", eachResult[self.EPH_NDX])
            print("Salt:          ", eachResult[salt + str(fileSize)])

    def PrettyResults(self):
        
        # Create Pretty Table with Heading
        t = PrettyTable(['Path',self.HASHTYPE,'Size','Last-Mod', 'Last-Acc','Created', 'Extension', 'Epoch'])
        
        for r in self.resultList:
            sz = '{:,}'.format(r[self.SIZ_NDX])
            t.add_row( [ r[self.FIL_NDX], r[self.HAS_NDX], sz, r[self.MOD_NDX], r[self.ACC_NDX], r[self.CRE_NDX], r[self.EXT_NDX], r[self.EPH_NDX]] )                    
        
        t.align = "l" 
        
        tabularResults = t.get_string()
        print(tabularResults)

        try:
            with open("result.txt", 'w') as outFile:
                outFile.write(tabularResults)    
                print("Pretty Table Result File:   results.txt   Created")
        except Exception as err:
            print("Failed: PrettyTable File Save: ",str(err))

    def CSVResults(self):
        
        try:
            with open("resultCSV.csv", 'w') as outFile:
         
                # Create CSV Heading
                heading = 'Path'+','+self.HASHTYPE+','+'Size'+','+'Last-Mod'+','+'Last-Acc'+','+'Created'+','+'Extension'+','+'Epoch'+'\n'
                outFile.write(heading)
                
                for r in self.resultList:
                    
                    mt = "'"+r[self.MOD_NDX]+"'"
                    at = "'"+r[self.ACC_NDX]+"'"
                    ct = "'"+r[self.CRE_NDX]+"'"
                    sz = str(r[self.SIZ_NDX])
                    
                    outFile.write(r[self.FIL_NDX]+','+r[self.HAS_NDX]+','+sz+','+mt+','+at+','+ct+','+r[self.EXT_NDX]+','+str(r[self.EPH_NDX])+'\n')                    
    
                print("\nResult CSV File Created: result.csv\n")
                
        except Exception as err:
            print("Failed: CSV File Save: ",str(err))            


#NTP Request

if __name__ == "__main__":
    ''' Main Script Entry Point '''
    
    print("\nGet Network Time version 1.0 \n")
    
    with closing(socket( AF_INET, SOCK_DGRAM)) as s:  # Open a Socket and close automatically once completed
        s.sendto(NTP_QUERY, (URL, PORT))              # Send the NTP Query to pool.ntp.org     
        msg, address = s.recvfrom(1024)               # Wait for the response
        
        # unpack the results using struct and the known format
        # which is Big Endian (!) 12 Unsigned Integers (4 bytes each)
        
        unpackedResponse = struct.unpack(NTP_PACKET_FORMAT, msg[0:struct.calcsize(NTP_PACKET_FORMAT)])
    
    '''
    For our purpose the unpacked response values 
    offset[10] = Seconds
    offset[11] = MicroSeconds
    '''
    
    seconds       = float(unpackedResponse[SECONDS])
    microseconds  = float(unpackedResponse[MICRO_SECONDS]) / 2**32
    
    '''
    to calcuate the final epoch value we need to 
    combine the seconds and microseconds and deduct the NTP_DELTA
    note, the NTP Delta for Windows is the epoch value from January 1, 1970
    '''
    epoch    = seconds + microseconds - NTP_DELTA
    
    timeValue     = time.gmtime(epoch)           # Convert to UTC Time Value
                                                 # Then convert to human readable form
    humanReadable = time.strftime("%m/%d/%Y %H:%M:%S UTC", timeValue)
    
    print(humanReadable)                        # Print Human Readable Value


        
if __name__ == '__main__':

    PFISH_VERSION = '2.1 July 2019 Python 3.x and 2.x Version'

    # Record the Starting Time
    startTime = time.time()
    
    print('Wecome to p-fish ... version '+ PFISH_VERSION,"\n\n")
    
    # instantiate a pFishObject
    pFishObject = FileHasher()
    
    print("User Input")
    print("----------")
    print("Root Path Selection: ", pFishObject.ROOTPATH)
    print("Hash Type Selection: ", pFishObject.HASHTYPE,"\n")
    
    # Traverse the file system directories and hash the files
    pFishObject.ProcessFiles()
    
    if PRETTY:
        ''' if prettytable library available '''
        pFishObject.PrettyResults()
    else:
        ''' otherwise a simple dump '''
        pFishObject.DumpResults()

    pFishObject.CSVResults()  
    
    # Record the end time and calculate the duration
    endTime = time.time()
    duration = endTime - startTime

    print('Files Processed: ', '{:,}'.format(pFishObject.processCount))
    print('Hashed Bytes:    ', '{:,}'.format(pFishObject.processSize)," Bytes")
    print('Error Count:     ', '{:,}'.format(pFishObject.errorCount))    
    print('Elapsed Time:    ', '{:.2f}'.format(duration) + ' seconds\n')
    print('Program Terminated Normally')

    
    

