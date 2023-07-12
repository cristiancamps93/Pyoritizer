# Cristian Camps Morillo - Getronics - Mitre Coverage Project
"""
Abstract:
    This script is created to know what techniques prioritize and ignore covered techniques.
    To do so, we are gathering all the techniques given in the monthly TA Profiling report./
    Removing empty techniques, merging duplicated ones. Deleting the ones covered and sorting by Actor Count.


#VERSION CONTROL
Version 1.0:
    23/06/2023: First version

"""
import csv

# IMPORTS
import pandas as pd
import time
import numpy as np
import csv


# DISCLAIMER
print("Hello, please re-fill the excels found in the same folder called 'inputCTI.csv' and 'inputCoverage.csv' with the same pattern.")
print("")
print("Notice that the input file must be encoded in UTF-8, otherwise the script won't work :)")
print("")
print("Please, be aware that in terms of coverage, the technique that matters is the last one. So if a technique has different states, the last one is the one in count")
print("")
print("Once executed, this script will provide a json file that needs to be imported into the Mitre web application.")
input("Press any key to execute:")


# CONSTANTS
outputFile = "output.csv"
inputCTI = "inputCTI.csv"
inputCoverage = "inputCoverage.csv"



# Import data from the input CTI as pandas object
def importDataCTI(inputF):
    # IMPORT INPUT DATA FROM CTI
    # TechID;Sum
    mitre = pd.read_csv(inputF, sep=';')
    mitre = mitre.dropna()
    return mitre

#Analyze data from CTI, removing 0s
def sortPandaCTI(panda):

    #Reading Columns and bulking into lists
    TechID = list(panda["TechID"])
    Sum = list(panda['Sum'])


    # Dropping all the rows where Sum = 0
    it = 0
    SumNo = []
    TechIDNo = []

    for line in Sum:
        if line != 0:
            SumNo.append(Sum[it])
            TechIDNo.append(TechID[it])
        it = it + 1

    #Merging Duplicated Values
    it = 0
    FinalSum = []
    FinalTech = []

    for line in TechIDNo:
        it2 = 0
        hits = 0

        for line2 in TechIDNo:
            if line == line2:
                hits = hits + 1


            if hits == 2:
                FinalTech.append(line)
                FinalSum.append(max(SumNo[it], SumNo[it2]))
                hits = 0
            it2 = it2 + 1
        it = it + 1


    #Control that the techniques and plays have the same amount of fields
    if len(FinalTech) - len(FinalSum) == 0:
        return FinalTech, FinalSum
    else:
        print("Import error in TechID or Sum, please check that both fields contain the same amount of data")

# Import data from the input Coverage as pandas object
def importDataCoverage(inputF):
    # IMPORT INPUT DATA FROM Coverage
    # ID;Play ID;Detection Rule Status
    mitre = pd.read_csv(inputF, sep=';')
    return mitre

#Analyze data from Coverage. Returning 2 lists, technique and boolean list if coverage = true
def sortPandaCoverage(panda):

    #Reading Columns and bulking into lists
    TechID = list(panda["ID"])
    Coverage = list(panda['Detection Rule Status'])

    it = 0

    for line in Coverage:
        if Coverage[it] == "Coverage in place":
            Coverage[it] = True
        else:
            Coverage[it] = False
        it = it + 1

    return TechID, Coverage


#Analyzes techniques, TA mapping and coverage and returns a list of techniques and CTI threat number of the techniques NOT COVERED
def checker (TechID, Sum, CoverageID, Coverage):

    it = 0
    id = []
    nota = []

    for line in TechID:
        it2 = 0
        for line2 in CoverageID:
            if TechID[it] == CoverageID[it2]:
                if Coverage[it2] == False:
                    id.append(TechID[it])
                    nota.append(Sum[it])

            it2 = it2 + 1


        it = it + 1

    #Control that the techniques and Sum have the same amount of fields
    if len(id) - len(nota) == 0:
        return id, nota
    else:
        print("Error in the checker function id and nota have not the same lenght.")

def exporter (id, nota):
    with open(outputFile, 'w', newline='') as file:
        file.write("Technique Not Covered;Sum")
        file.write("\n")

        it = 0
        for line in id:
            row = str(id[it]) + ";" + str(nota[it])
            file.write(row)
            file.write("\n")

            it = it + 1


if __name__ == "__main__":
    CTI = importDataCTI(inputCTI)
    Coverage = importDataCoverage(inputCoverage)
    TechID, Sum= sortPandaCTI(CTI)
    CoverageID, Coverage = sortPandaCoverage(Coverage)
    id, nota = checker(TechID, Sum, CoverageID, Coverage)
    exporter(id, nota)