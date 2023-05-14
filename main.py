import json
import os
import glob
import pprint
import argparse
import matplotlib.pyplot as plt

def read_files_of_year(year):
    result = []
    path = './cves/' + str(year)
    for root, dirs, files in os.walk(path):
        for file in files:
            result.append(os.path.join(root, file))
            
    return result

def calc_median_year(year, cvss_version):
    counter = 0
    median_base_score = 0
    files_to_read = read_files_of_year(year)
    for file in files_to_read:
        base_score = parse_json_base_score(file, cvss_version)
        if base_score:
            median_base_score = median_base_score + base_score
            counter = counter + 1
    if counter:
        return median_base_score / counter 

def parse_json_base_score(filename, cvss_version):
    counter = 0
    result = 0
    f = open(filename)
    j = json.load(f)
    if 'metrics' in j['containers']['cna']:
        metrics = j['containers']['cna']['metrics']
        for metric in metrics:
            match cvss_version:
                case '3_1':
                    if 'cvssV3_1' in metric:
                        result = result + float(metric['cvssV3_1']['baseScore'])
                        counter = counter + 1
                case '3_0':
                    if 'cvssV3_0' in metric:
                        result = result + float(metric['cvssV3_0']['baseScore'])
                        counter = counter + 1
                case '2_0':
                    if 'cvssV2_0' in metric:
                        result = result + float(metric['cvssV2_0']['baseScore'])
                        counter = counter + 1
    if counter > 0:
        return result / counter
    else:
        return

def get_all_crits_year(year, cvss_version):
    result = []
    files_to_read = read_files_of_year(year)
    for file in files_to_read:
        crit = parse_json_crits(file, cvss_version)
        if crit:
            result.append(crit)
    
    return result

def parse_json_crits(filename, cvss_version):
    result = {}
    f = open(filename)
    j = json.load(f)
    if 'metrics' in j['containers']['cna']:
        metrics = j['containers']['cna']['metrics']
        for metric in metrics:
            match cvss_version:
                case '3_1':
                    if 'cvssV3_1' in metric:
                        if 9.0 <= float(metric['cvssV3_1']['baseScore']):
                            result['id'] = j['cveMetadata']['cveId']
                            result['cvss'] = float(metric['cvssV3_1']['baseScore'])
                            if 'title' in j['containers']['cna']:
                                result['title'] = j['containers']['cna']['title']
                            else: 
                                result['title'] = ""
                case '3_0':
                    if 'cvssV3_0' in metric:
                        if 9.0 <= float(metric['cvssV3_0']['baseScore']):
                            result['id'] = j['cveMetadata']['cveId']
                            result['cvss'] = float(metric['cvssV3_0']['baseScore'])
                            if 'title' in j['containers']['cna']:
                                result['title'] = j['containers']['cna']['title']
                            else: 
                                result['title'] = ""
                case '2_0':
                    if 'cvssV2_0' in metric:
                        if 9.0 <= float(metric['cvssV2_0']['baseScore']):
                            result['id'] = j['cveMetadata']['cveId']
                            result['cvss'] = float(metric['cvssV2_0']['baseScore'])
                            if 'title' in j['containers']['cna']:
                                result['title'] = j['containers']['cna']['title']
                            else: 
                                result['title'] = ""                
    return result

def add_years_between(year_range):
    splitted_years = year_range.split('-')
    result = []
    for i in range(int(splitted_years[0]), int(splitted_years[1]) + 1):
        result.append(i)
        
    return result

'''   
def plot_data(data):
    x = [1, 1, 2, 3, 3, 5, 7, 8, 9, 10,
        10, 11, 11, 13, 13, 15, 16, 17, 18, 18,
        18, 19, 20, 21, 21, 23, 24, 24, 25, 25,
        25, 25, 26, 26, 26, 27, 27, 27, 27, 27,
        29, 30, 30, 31, 33, 34, 34, 34, 35, 36,
        36, 37, 37, 38, 38, 39, 40, 41, 41, 42,
        43, 44, 45, 45, 46, 47, 48, 48, 49, 50,
        51, 52, 53, 54, 55, 55, 56, 57, 58, 60,
        61, 63, 64, 65, 66, 68, 70, 71, 72, 74,
        75, 77, 81, 83, 84, 87, 89, 90, 90, 91
        ]
    
    plt.hist(x, bins=5)
    plt.show()
'''

if __name__ == '__main__':       
    parser = argparse.ArgumentParser(description='Search a specific year of CVEs')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--year', type=int, help='the year you want to process')
    group.add_argument('--range', help='range of years. example: 2010-2023')
    parser.add_argument('--version', help='version of cvss', choices=['3_1', '3_0', '2_0'], default='3_1',required=False)
    parser.add_argument('--crit', help='search CVEs with CVSS >=9', action='store_true')
    args = parser.parse_args()
    
    result_dict = {}
    #Calculate Median of one year
    if args.year:
        result_dict[args.year] = calc_median_year(args.year, args.version)
        if args.crit:
            crits_of_year = get_all_crits_year(args.year, args.version)
            for crit in crits_of_year:
                print(crit)
            print("Year " + str(args.year) + " has " + str(len(crits_of_year)) + " CVEs with CVSS " + args.version + " >= 9.0")
        
    #calculate median of every year
    if args.range:
        years = add_years_between(args.range)
        for y in years:
            result_dict[y] = calc_median_year(y, args.version)
          
    print(result_dict)

    #print(parse_json_base_score('cves/2022/35xxx/CVE-2022-35875.json'))
    #plot_data(1)