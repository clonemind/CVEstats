import json
import os
from pathlib import Path
import argparse
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

files_to_read = []

def open_file(filename):
    return open(filename, encoding='utf-8')
    
def read_files_of_year(year):
    global files_to_read
    files_to_read = []
    path = Path(os.getcwd() + '/cves/' + str(year))
    for root, dirs, files in os.walk(path):
        for file in files:
            files_to_read.append(os.path.join(root, file))

def calc_median_year(year, cvss_version):
    counter = 0
    median_base_score = 0
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
    f = open_file(filename)
    j = json.load(f)
    if 'metrics' in j['containers']['cna']:
        metrics = j['containers']['cna']['metrics']
        for metric in metrics:
            for version in cvss_version:
                if version == '3_1':
                    if 'cvssV3_1' in metric:
                        result = result + float(metric['cvssV3_1']['baseScore'])
                        counter = counter + 1
                elif version == '3_0':
                    if 'cvssV3_0' in metric:
                        result = result + float(metric['cvssV3_0']['baseScore'])
                        counter = counter + 1
                elif version == '2_0':
                    if 'cvssV2_0' in metric:
                        result = result + float(metric['cvssV2_0']['baseScore'])
                        counter = counter + 1
                    
    if counter > 0:
        return result / counter
    else:
        return

def get_all_crits_year(year, cvss_version):
    result = []
    for file in files_to_read:
        crit = parse_json_crits(file, cvss_version)
        if crit:
            result.append(crit)
    
    return result

def parse_json_crits(filename, cvss_version):
    result = {}
    f = open_file(filename)
    j = json.load(f)
    if 'metrics' in j['containers']['cna']:
        metrics = j['containers']['cna']['metrics']
        for metric in metrics:
            for version in cvss_version:
                if version == '3_1':
                    if 'cvssV3_1' in metric:
                        if 9.0 <= float(metric['cvssV3_1']['baseScore']):
                            result['id'] = j['cveMetadata']['cveId']
                            result['cvss'] = float(metric['cvssV3_1']['baseScore'])
                            if 'title' in j['containers']['cna']:
                                result['title'] = j['containers']['cna']['title']
                            else: 
                                result['title'] = ""
                elif version == '3_0':
                    if 'cvssV3_0' in metric:
                        if 9.0 <= float(metric['cvssV3_0']['baseScore']):
                            result['id'] = j['cveMetadata']['cveId']
                            result['cvss'] = float(metric['cvssV3_0']['baseScore'])
                            if 'title' in j['containers']['cna']:
                                result['title'] = j['containers']['cna']['title']
                            else: 
                                result['title'] = ""
                elif version == '2_0':
                    if 'cvssV2_0' in metric:
                        if 9.0 <= float(metric['cvssV2_0']['baseScore']):
                            result['id'] = j['cveMetadata']['cveId']
                            result['cvss'] = float(metric['cvssV2_0']['baseScore'])
                            if 'title' in j['containers']['cna']:
                                result['title'] = j['containers']['cna']['title']
                            else: 
                                result['title'] = ""                
    return result

# generates a list of cwes 
def get_all_cwe_year(year, cwe):
    result = []
    cwe_title = None
    for file in files_to_read:
        cve_id, cwe_description = parse_json_cwe(file, cwe)
        if cve_id:
            result.append(cve_id)
        if not cwe_title and cwe_description:
            cwe_title = cwe_description
    
    return result, cwe_title

# search the all CVEs which is related to the mentioned CWE
def parse_json_cwe(filename, cwe):
    f = open_file(filename)
    j = json.load(f)
    if 'problemTypes' in j['containers']['cna']:
        problems = j['containers']['cna']['problemTypes']
        for problem in problems:
            for description in problem['descriptions']:
                if 'cweId' in description:
                    if cwe == description['cweId']:
                        return j['cveMetadata']['cveId'], description['description']
    return None, None

# generate a list of all CVEs with the mentioned product
def get_all_products_year(year, product):
    result = []
    for file in files_to_read:
        cve = parse_json_product(file, product)
        if cve:
            result.append(cve)

    return result

def parse_json_product(filename, product):
    f = open_file(filename)
    j = json.load(f)
    if 'affected' in j['containers']['cna']:
        affected_product = j['containers']['cna']['affected']
        for product_data in affected_product:
            if product.lower() in product_data['product'].lower():
                return j['cveMetadata']['cveId']
    return None

# generate a list of all CVEs with the mentioned vendor
def get_all_vendors_year(year, vendor):
    result = []
    for file in files_to_read:
        cve = parse_json_vendor(file, vendor)
        if cve:
            result.append(cve)

    return result

def parse_json_vendor(filename, vendor):
    f = open_file(filename)
    j = json.load(f)
    if 'affected' in j['containers']['cna']:
        affected_vendor = j['containers']['cna']['affected']
        for vendor_data in affected_vendor:
            if vendor.lower() in vendor_data['vendor'].lower():
                return j['cveMetadata']['cveId']
    return None

def get_all_rejected_year(year):
    result = []
    for file in files_to_read:
        rejected = parse_json_rejected(file)
        result.append(rejected)
    
    return result

def parse_json_rejected(filename):
    f = open_file(filename)
    j = json.load(f)
    if 'cveMetadata' in j:
        if "rejected" == (j['cveMetadata']['state']).lower():
            return j['cveMetadata']['cveId']

def get_all_credits_year(year):
    result = {}
    for file in files_to_read:
        credits = parse_json_credits(file)
        for credit in credits:
            if credit in result:
                result[credit] += 1
            elif credit not in result:
                result[credit] = 1
    return result

def parse_json_credits(filename):
    result = []
    f = open_file(filename)
    j = json.load(f)
    if 'credits' in j['containers']['cna']:
        credits = j['containers']['cna']['credits']
        for credit in credits:
            #print(credit['value'])
            result.append(credit['value'])
    return result

def parse_year(year):
    result = []
    if '-' in year:
        splitted_years = year.split('-')
        for i in range(int(splitted_years[0]), int(splitted_years[1]) + 1):
            result.append(i)
    else:
        result.append(str(year))
        
    return result

def calc_plot_num(data, years):
    # 1 because cris will always ploted
    result = 0
    if 'crit' in data[years[0]]: result += 1
    if 'cwe' in data[years[0]]:result += 1
    if 'product' in data[years[0]]:result += 1
    if 'vendor' in data[years[0]]:result += 1
    if 'rejected' in data[years[0]]:result += 1
    if 'credits' in data[years[0]]:result += 1
    return result

def plot_data(data, cvss_version):
    keys = data.keys()
    year_list = []
    median_list = []
    crit_list = []
    cwe_list = []
    product_list = []
    vendor_list = []
    rejected_list = []
    credits_list = []   
    
    # generate a list with all years that the user wants
    for years in keys:
        year_list.append(years)
        
    # calculate a list to plot median
    for year in year_list:
        if data[year]['median'] is None:
            median_list.append(0)
        else:
            median_list.append(data[year]['median'])
            
    # calculate the number of plots which have to be generated
    num_plots = calc_plot_num(data, year_list)
    figure, axis = plt.subplots(1, num_plots + 1)
    year = year_list[0] # assign any year to this variable, to check later in the code for crit and cwe keyword
    
    if 'crit' in data[year]:
        for year in year_list:
            if data[year]['crit'] is not None:
                crit_list.append(data[year]['crit']['num'])

        # Plot crits       
        axis[num_plots].set_title("Critical vulns from " + str(year_list[0]) + " to " + str(year_list[-1]))
        bars = axis[num_plots].bar(keys, crit_list)
        axis[num_plots].set(xlabel='years', ylabel='num crits')
        axis[num_plots].yaxis.set_major_locator(MaxNLocator(integer=True)) # set x axis to integers
        axis[num_plots].set_ylim(bottom=0) # y min is always 0
        axis[num_plots].set_xticks(year_list, year_list, rotation=90)
        axis[num_plots].bar_label(bars)
        num_plots -= 1
    
    if 'cwe' in data[year]:
        for year in year_list:
            if data[year]['cwe'] is not None:
                cwe_list.append(data[year]['cwe']['num'])
        
        # Plot CWE      
        axis[num_plots].set_title(data[year]['cwe']['title'] + " from " + str(year_list[0]) + " to " + str(year_list[-1]))
        bars = axis[num_plots].bar(keys, cwe_list)
        axis[num_plots].set(xlabel='years', ylabel='num assigned CWEs')
        axis[num_plots].yaxis.set_major_locator(MaxNLocator(integer=True)) # set x axis to integers
        axis[num_plots].set_ylim(bottom=0) # y min is always 0
        axis[num_plots].set_xticks(year_list, year_list)
        axis[num_plots].bar_label(bars)
        num_plots -= 1
    
    if 'product' in data[year]:
        for year in year_list:
            if data[year]['product'] is not None:
                product_list.append(data[year]['product']['num'])
        
        # Plot Product CVEs    
        axis[num_plots].set_title(data[year]['product']['title'] + " vulns from " + str(year_list[0]) + " to " + str(year_list[-1]))
        bars = axis[num_plots].bar(keys, product_list)
        axis[num_plots].set(xlabel='years', ylabel='num of vulns')
        axis[num_plots].yaxis.set_major_locator(MaxNLocator(integer=True)) # set x axis to integers
        axis[num_plots].set_ylim(bottom=0) # y min is always 0
        axis[num_plots].set_xticks(year_list, year_list)
        axis[num_plots].bar_label(bars)
        num_plots -= 1
        
    if 'vendor' in data[year]:
        for year in year_list:
            if data[year]['vendor'] is not None:
                vendor_list.append(data[year]['vendor']['num'])
        
        # Plot vendor CVEs    
        axis[num_plots].set_title(data[year]['vendor']['title'] + " vulns from " + str(year_list[0]) + " to " + str(year_list[-1]))
        bars = axis[num_plots].bar(keys, vendor_list)
        axis[num_plots].set(xlabel='years', ylabel='num of vulns')
        axis[num_plots].yaxis.set_major_locator(MaxNLocator(integer=True)) # set x axis to integers
        axis[num_plots].set_ylim(bottom=0) # y min is always 0
        axis[num_plots].set_xticks(year_list, year_list)
        axis[num_plots].bar_label(bars)
        num_plots -= 1
            
    if 'rejected' in data[year]:
        for year in year_list:
            if data[year]['rejected'] is not None:
                rejected_list.append(data[year]['rejected']['num'])
        
        # Plot vendor CVEs    
        axis[num_plots].set_title("rejected CVEs")
        bars = axis[num_plots].bar(keys, rejected_list)
        axis[num_plots].set(xlabel='years', ylabel='num of rejected')
        axis[num_plots].yaxis.set_major_locator(MaxNLocator(integer=True)) # set x axis to integers
        axis[num_plots].set_ylim(bottom=0) # y min is always 0
        axis[num_plots].set_xticks(year_list, year_list)
        axis[num_plots].bar_label(bars)
        num_plots -= 1
        
    if 'credits' in data[year]:
        for year in year_list:
            if data[year]['credits'] is not None:
                rejected_list.append(data[year]['credits']['num'])
        
        # Plot vendor CVEs    
        axis[num_plots].set_title("CVEs with credits")
        bars = axis[num_plots].bar(keys, rejected_list)
        axis[num_plots].set(xlabel='years', ylabel='num of credits')
        axis[num_plots].yaxis.set_major_locator(MaxNLocator(integer=True)) # set x axis to integers
        axis[num_plots].set_ylim(bottom=0) # y min is always 0
        axis[num_plots].set_xticks(year_list, year_list)
        axis[num_plots].bar_label(bars)
        num_plots -= 1
        
    # Plot median        
    axis[num_plots].set_title('CVSS ' + str(cvss_version) + " >= 9,0 from " + str(year_list[0]) + " to " + str(year_list[-1]))
    bars = axis[num_plots].bar(keys, median_list)
    axis[num_plots].set(xlabel='years', ylabel='CVSS')
    axis[num_plots].yaxis.set_major_locator(MaxNLocator(integer=True)) # set x axis to integers
    #axis[num_plots].set_ylim(bottom=0) # y min is always 0
    axis[num_plots].set_xticks(year_list, year_list)
    axis[num_plots].bar_label(bars)
        
    plt.show()

def gui(args):
    result_dict = {}
    years = parse_year(args.year)
    for y in years:
        read_files_of_year(y)
        result_dict[y] = {}
        result_dict[y]['median'] = calc_median_year(y, args.version)
        if args.crit:
            crits_of_year = get_all_crits_year(y, args.version)
            if args.v is not None:
                for crit in crits_of_year:
                    print(crit)
            print(str(y) + ": " + str(len(crits_of_year)) + " CVEs with CVSS " + str(args.version) + " >= 9.0")
            result_dict[y]['crit'] = {'num': len(crits_of_year)}
        
        if args.cwe:
            cves_relatet_to_cwe, cwe_title = get_all_cwe_year(y, args.cwe)
            if args.v is not None:
                for cve in cves_relatet_to_cwe:
                    print(args.cwe + ": " + cve)
            print(str(y) + ": " + str(len(cves_relatet_to_cwe)) + " vulnerabilities have " + args.cwe + '(' + str(cwe_title) + ')' + " assigned")
            result_dict[y]['cwe'] = {}
            result_dict[y]['cwe']['title'] = args.cwe
            result_dict[y]['cwe']['num'] = len(cves_relatet_to_cwe)
        
        if args.product:
            cves_relatet_to_product = get_all_products_year(y, args.product)
            if args.v is not None:
                for cve in cves_relatet_to_product:
                    print(args.product + ": " + cve)
            print(str(y) + ": " + "The product " + args.product + " has " + str(len(cves_relatet_to_product)) + " vulnerabilities assigned")
            result_dict[y]['product'] = {}
            result_dict[y]['product']['title'] = args.product
            result_dict[y]['product']['num'] = len(cves_relatet_to_product)
        
        if args.vendor:
            cves_relatet_to_vendor = get_all_vendors_year(y, args.vendor)
            if args.v is not None:
                for cve in cves_relatet_to_vendor:
                    print(args.vendor + ": " + cve)
            print(str(y) + ": " + "The vendor " + args.vendor + " has " + str(len(cves_relatet_to_vendor)) + " vulnerabilities assigned")
            result_dict[y]['vendor'] = {}
            result_dict[y]['vendor']['title'] = args.vendor
            result_dict[y]['vendor']['num'] = len(cves_relatet_to_vendor)

        if args.rejected:
            rejected_cves = get_all_rejected_year(y)
            if args.v is not None:
                for cve in rejected_cves:
                    print("REJECTED: " + cve)
            print(str(y) + ": " + str(len(rejected_cves)) + " rejected CVEs")
            result_dict[y]['rejected'] = {'num': len(rejected_cves)}
            
        if args.credits:
            credits_cves = get_all_credits_year(y)
            num_credits = 0
            sorted_credits = dict(sorted(credits_cves.items(), key=lambda item: item[1], reverse=True))
            list_of_credits = list(sorted_credits.items())
            if args.v is not None:
                print("\nTop ten credits earner:")
                for i in range(0, 10):
                    try:
                        print(str(i + 1) + ". " + str(list_of_credits[i][0]) + " : " + str(list_of_credits[i][1]))
                    except:
                        pass
            
            for l in list_of_credits:
                num_credits += l[1]
            print(str(y) + ": " + str(num_credits) + " credits in CVEs")
            result_dict[y]['credits'] = {'num': str(num_credits)}
            
    print(result_dict)
    
    if args.show:
        plot_data(result_dict, args.version)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='search a specific year of CVEs')
    parser.add_argument('-V', '--version', help='version of CVSS: 3_1, 3_0, 2_0', nargs='*', default='3_1',required=True)
    parser.add_argument('-v', help='--verbose', action='append_const', const = 1)
    parser.add_argument('--year', help='the year you want to process. e.g.: 2022 or 2022-2023', required=True)
    parser.add_argument('--crit', help='only search CVEs with CVSS >=9', action='store_true')
    parser.add_argument('--cwe', help='Search CVEs with CWE categories')
    parser.add_argument('--product', help='search for vulns of a specific product')
    parser.add_argument('--vendor', help='search for vulns of a specific vendor')
    parser.add_argument('--rejected', help='search rejected CVE IDs', action='store_true')
    parser.add_argument('--credits', help='search credits to researchers', action='store_true')
    parser.add_argument('-s', '--show', help='plots data of CVEs', action='store_true')

    args = parser.parse_args()
    
    gui(args)