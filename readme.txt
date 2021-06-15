# The purpose of this script is to peform a foresic time stamp of files
# This script has been modified to to add the epoch time
# Read about epect time here: https://en.wikipedia.org/wiki/Epoch_(computing) and https://www.foxtonforensics.com/blog/post/timestamps-in-internet-history
# This script will output the following: path - hash value - file size - last modification - last accessed - created - extension - epoch time
# This script will also output a results.txt file and a CSV with the results
# The files must reside in the same folder as the script
# The variables you will need when running this script in Wing IDE is: -d ./_name_of_folder --md5
# Syntax for hashes: 
                     --md5
                     --sha1
                    --sha256
                    --sha512