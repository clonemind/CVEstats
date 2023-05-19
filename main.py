import json
import os
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

def get_all_cwe_year(year, cwe):
    result = []
    cwe_title = None
    files_to_read = read_files_of_year(year)
    for file in files_to_read:
        cve, cwe_description = parse_json_cwe(file, cwe)
        if cve:
            result.append(cve)
        if not cwe_title and cwe_description:
            cwe_title = cwe_description
    
    return result, cwe_title
    
def parse_json_cwe(filename, cwe):
    f = open(filename)
    j = json.load(f)
    if 'problemTypes' in j['containers']['cna']:
        problems = j['containers']['cna']['problemTypes']
        for problem in problems:
            for description in problem['descriptions']:
                if 'cweId' in description:
                    if cwe == description['cweId']:
                        return j['cveMetadata']['cveId'], description['description']
    return None, None

def parse_year(year):
    result = []
    if '-' in year:
        splitted_years = year.split('-')
        for i in range(int(splitted_years[0]), int(splitted_years[1]) + 1):
            result.append(i)
    else:
        result.append(str(year))
        
    return result

def plot_data(data, cvss_version ):
    keys = data.keys()
    year_list = []
    median_list = []
    crit_list = []
    cwe_list = []
    figure, axis = plt.subplots(1, 2)
    
    for years in keys:
        year_list.append(years)
    for year in year_list:
        if data[year]['median'] is None:
            median_list.append(0)
        else:
            median_list.append(data[year]['median'])
    if 'crit' in data[year]:
        for year in year_list:
            if data[year]['crit'] is not None:
                crit_list.append(data[year]['crit']['num'])
        
        # Plot crits       
        axis[1].set_title("Critical vulns from " + str(year_list[0]) + " to " + str(year_list[-1]))
        axis[1].plot(data.keys(), crit_list)
        axis[1].set(xlabel='years', ylabel='num crits')
    
    if 'cwe' in data[year]:
        for year in year_list:
            if data[year]['cwe'] is not None:
                cwe_list.append(data[year]['cwe']['num'])    
        
        # Plot CWE      
        axis[1].set_title(data[year]['cwe']['title'] + " from " + str(year_list[0]) + " to " + str(year_list[-1]))
        axis[1].plot(data.keys(), cwe_list)
        axis[1].set(xlabel='years', ylabel='num assigned CWEs')
        
    # Plot median        
    axis[0].set_title('CVSS ' + cvss_version + " from " + str(year_list[0]) + " to " + str(year_list[-1]))
    axis[0].bar(data.keys(), median_list)
    axis[0].set(xlabel='years', ylabel='CVSS')

    plt.show()

def gui(args):
    result_dict = {}
    years = parse_year(args.year)
    for y in years:
        result_dict[y] = {}
        result_dict[y]['median'] = calc_median_year(y, args.version)
        if args.crit:
            crits_of_year = get_all_crits_year(y, args.version)
            if args.v is not None:
                for crit in crits_of_year:
                    print(crit)
            print(str(y) + ": " + str(len(crits_of_year)) + " CVEs with CVSS " + args.version + " >= 9.0")
            result_dict[y]['crit'] = {'num': len(crits_of_year)}
        elif args.cwe:
            cves_relatet_to_cwe, cwe_title = get_all_cwe_year(y, args.cwe)
            if args.v is not None:
                for cve in cves_relatet_to_cwe:
                    print(cve)
            print(str(y) + ": " + str(len(cves_relatet_to_cwe)) + " vulnerabilities have " + args.cwe + '(' + str(cwe_title) + ')' + " assigned")
            result_dict[y]['cwe'] = {}
            result_dict[y]['cwe']['title'] = args.cwe
            result_dict[y]['cwe']['num'] = len(cves_relatet_to_cwe)

    print(result_dict)
    
    if args.plot:
        plot_data(result_dict, args.version)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search a specific year of CVEs')
    parser.add_argument('-V', '--version', help='version of CVSS', choices=['3_1', '3_0', '2_0'], default='3_1',required=False)
    parser.add_argument('-p', '--plot', help='plots data of CVEs', action='store_true')
    parser.add_argument('-v', help='--verbose', action='append_const', const = 1)
    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument('-c', '--crit', help='search CVEs with CVSS >=9', action='store_true')
    group1.add_argument('-C', '--cwe', help='Search for CWE categories')
    parser.add_argument('-y', '--year', help='the year you want to process. e.g.: 2022 or 2022-2023', required=True)
    args = parser.parse_args()
    
    gui(args)