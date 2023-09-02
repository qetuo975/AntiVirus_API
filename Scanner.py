import hashlib
import os
import sys
import time
import threading
import re
import requests
import hashlib
from collections import deque
from urllib.parse import urlparse
from pprint import pprint

HA_API = ""
VT_API = ""
#HA_API = ""
FILES = "takip.html"


class HybritAnalysis:
    def __init__(self):
        self.HybritAnalysis_API = HA_API

        # URL
        # ----------------------------------
        self.QuickScanner_URL = "https://www.hybrid-analysis.com/api/v2/quick-scan/url"
        self.QuickScanner_FILE = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
        self.SandBox_FILE = "https://www.hybrid-analysis.com/api/v2/submit/file"
        self.SandBox_REPORT = "https://www.hybrid-analysis.com/api/v2/report/summary"
        self.SandBox_URL = "https://www.hybrid-analysis.com/api/v2/submit/url"
        self.ReportDeque_URL = deque(maxlen=50)
        self.ReportDeque_FILE = deque(maxlen=50)


        self.MultiProccess_GET_REPORT = threading.Thread(target=self.getReport, daemon=True)
        self.MultiProccess_GET_REPORT.start()

        # ----------------------------------



    def getReport(self):
        while True:
            time.sleep(3)

            if len(self.ReportDeque_URL) > 0:

                for i in self.ReportDeque_URL:
                    time.sleep(0.2)
                    Response = self.HybritAnalysis_GET_REPORT(ID=i.get('id'))
                    pprint(Response)
                    exit()

                    if Response.get('finished') == True:
                        self.HybritAnalysis_URL_PRINTER(ResponseReport=Response, URL=i.get('url'))
                        self.ReportDeque_URL.remove(i)
                        print("Remove Deque ID : ", i.get("id"))

            if len(self.ReportDeque_FILE) > 0:

                for i in self.ReportDeque_FILE:
                    time.sleep(0.2)
                    Response = self.HybritAnalysis_GET_REPORT(ID=i.get('id'))

                    if Response.get('finished') == True:
                        self.HybritAnalysis_FILE_PRINTER(ResponseReport=Response, FILE=i.get('file'))
                        self.ReportDeque_FILE.remove(i)
                        print("Remove Deque ID : ", i.get("id"))

    def HybritAnalysis_GET_REPORT(self, ID):
        ReportURL = f"https://www.hybrid-analysis.com/api/v2/quick-scan/{ID}"
        ReportHeader = \
        {
            "api-key": self.HybritAnalysis_API,
            "user-agent": "Falcon Sandbox",
        }

        Response = requests.get(ReportURL, headers=ReportHeader)

        if str(Response.status_code)[0] == "2":
            return Response.json()

        else:
            print("Error: ", Response.status_code)


    def HybritAnalysis_URL_SCANNER(self, URL):
        print("Taranıyor : Hybrit Analysis URL Quick Scanner !")

        Headers = \
        {
            "api-key": self.HybritAnalysis_API,
            "user-agent": "Falcon Sandbox"
        }

        Data = \
        {
            "url": URL,
            "scan_type": "all"
        }

        Response = requests.post(self.QuickScanner_URL, headers=Headers, data=Data)
        ResponseReport = Response.json()

        if ResponseReport.get("finished") == True:
            print(f"{URL} Send To Hybrit Analysis AI Systems")
            self.HybritAnalysis_URL_PRINTER(ResponseReport=ResponseReport, URL=URL)


        elif ResponseReport.get("finished") == False:
            self.ReportDeque_URL.append({"id": ResponseReport.get("reports"), "url":URL})
            print(f"{URL} Send to Report Queued.")

        else:
            print(f"Error Hybrit Analysis Post Status Code : {Response.status_code}")
        print("-----------------------------------------------\n")
    def HybritAnalysis_URL_PRINTER(self, ResponseReport, URL):
        if int(ResponseReport.get("scanners")[0].get("positives")) != 0:
            print(f"HybritAnalysis (VirüsTotal) Malware Detected : {URL}")

        elif ResponseReport.get("scanners")[1].get("positives") != None:
            print(f"HybritAnalysis (urlscan.io) Malware Detected : {URL}")

        elif ResponseReport.get("scanners_v2").get("bfore_ai").get("status") == "malicious" or ResponseReport.get(
                "scanners_v2").get("bfore_ai").get("status") == "suspicious":
            print(f"BFore AI Malware Detected : {URL}")


        elif ResponseReport.get("scanners_v2").get("clean_dns").get("status") == "malicious" or ResponseReport.get(
                "scanners_v2").get("clean_dns").get("status") == "suspicious":
            print(f"Clean DNS Malware Detected : {URL}")

        elif ResponseReport.get("scanners_v2").get("scam_adviser").get("status") == "malicious" or ResponseReport.get(
                "scanners_v2").get("scam_adviser").get("status") == "suspicious":
            print(f"Scam Adviser Malware Detected : {URL}")

        elif ResponseReport.get("scanners_v2").get("urlscan_io").get("status") == "malicious" or ResponseReport.get(
                "scanners_v2").get("scam_adviser").get("status") == "suspicious":
            print(f"urlscan.io Malware Detected : {URL}")

        elif int(ResponseReport.get("scanners_v2").get("virustotal").get("positives")) != 0:
            print(f"VirüsTotal Malware Detected : {URL}")

        else:
            print("Hybrit Analysis AI System Not Malware Detected !")


    def HybritAnalysis_FILE_SCANNER(self, FILE):
        print("Taranıyor : Hybrit Analysis File Quick Scanner !")

        File = \
        {
            "file": (FILE, open(FILE, "rb")),
            'scan_type': (None, 'all'),
        }

        Headers = \
        {
            "User-Agent": "Falcon Sandbox",
            "api-key": self.HybritAnalysis_API,
        }

        Response = requests.post(self.QuickScanner_FILE, headers=Headers, files=File)
        ResponseReport = Response.json()

        if ResponseReport.get("finished") == True:
            self.HybritAnalysis_FILE_PRINTER(Response.json(), FILE)

        elif ResponseReport.get("finished") == False:
            self.ReportDeque_FILE.append({"id": ResponseReport.get("reports"), "file":FILE})
            print(f"{FILE} Send to Report Queued.")

        else:
            print(f"Error Hybrit Analysis Status Code : {Response.status_code}")
        print("-----------------------------------------------\n")
    def HybritAnalysis_FILE_PRINTER(self, ResponseReport, FILE):
        if len(ResponseReport.get("scanners")[0].get("anti_virus_results")) > 0:
            print(f"CrowdStrike Falcon Static Analysis (ML) Malware Detected : {FILE}")

        elif len(ResponseReport.get("scanners")[1].get("anti_virus_results")) > 0:
            print(f"Metadefender Malware Detected : {FILE}")

        elif len(ResponseReport.get("scanners")[2].get("anti_virus_results")) > 0:
            print(f"VirusTotal Malware Detected : {FILE}")



        elif len(ResponseReport.get("scanners_v2").get("crowdstrike_ml").get("anti_virus_results")) > 0:
            print(f"Crowdstrike Machine Learning Malware Detected : {FILE}")
            print(ResponseReport.get("scanners_v2").get("crowdstrike_ml").get("anti_virus_results")[0])

        elif len(ResponseReport.get("scanners_v2").get("metadefender").get("anti_virus_results")) > 0:
            print(f"Metadefender Malware Detected : {FILE}")
            print(ResponseReport.get("scanners_v2").get("metadefender").get("anti_virus_results")[0])

        elif ResponseReport.get("scanners_v2").get("virustotal").get("positives") != 0:
            print(f"Virustotal Malware Detected : {FILE}")
            print(ResponseReport.get("scanners_v2").get("virustotal").get("positives"))

        else:
            print("Result : Hybrit Analysis File Quick Scanner Clear")

    def HybritAnalysis_SANDBOX_FILE_SCANNER(self, FILE):
        print("Taranıyor : Hybrit Analysis Sandbox File Scanner !")

        File = {"file": (FILE, open(FILE, "rb"))}
        Headers = \
        {
            "accept": "application/json",
            "User-Agent": "Falcon Sandbox",
            "api-key": self.HybritAnalysis_API,
        }

        Data = \
        {
            "environment_id": 120
        }

        Response = requests.post(self.SandBox_FILE, headers=Headers, files=File, data=Data)
        ResponseReport = Response.json()

        if str(Response.status_code)[0] == "2":
            print("Hybrit Analysis Sandbox Send File : ", FILE)
            self.HybritAnalysis_SANDBOX_REPORT(ID = ResponseReport.get("job_id"), DATA = FILE)

        else:
            print("Hybrit Analysis Sandbox Send Error : ", Response.status_code)

        print("-----------------------------------------------\n")
    def HybritAnalysis_SANDBOX_URL_SCANNER(self, URL):
        print("Taranıyor : Hybrit Analysis Sandbox URL Scanner !")
        Headers = \
        {
            "accept": "application/json",
            "User-Agent": "Falcon Sandbox",
            "api-key": self.HybritAnalysis_API,
        }

        Data = \
        {
            "url": URL,
            "environment_id": 120
        }

        Response = requests.post(self.SandBox_URL, headers=Headers, data=Data)
        ResponseReport = Response.json()

        if str(Response.status_code)[0] == "2":
            print("Hybrit Analysis Sandbox Send URL : ", URL)
            self.HybritAnalysis_SANDBOX_REPORT(ResponseReport.get("sha256"), URL)

        else:
            print("Hybrit Analysis Sandbox Send Error : ", Response.status_code)

        print("-----------------------------------------------\n")
    def HybritAnalysis_SANDBOX_REPORT(self, ID, DATA):
        Headers = \
        {
            "accept": "application/json",
            "user-agent": "Falcon Sandbox",
            "api-key": self.HybritAnalysis_API
        }

        data = \
        {
            "hashes[]": [ID]
        }

        Response = requests.post(self.SandBox_REPORT, headers=Headers, data=data)
        Report = Response.json()[0]

        # Succces
        if str(Response.status_code)[0] == "2":

            if Report.get("verdict") == "malicious" or Report.get("verdict") == "suspicious":
                print(f"{Report.get('environment_description')} Malware Detected ! : {DATA}")
            else:
                print(f"{Report.get('environment_description')} Not Malware Detected ! : {DATA}")
        else:
            print("Hybrit Analysis Sandbox Report Error : ", Response.status_code)
            print("-----------------------------------------------\n")

HB_ANALYSİS = HybritAnalysis()

class VirüsTotal:
    def __init__(self):
        self.VirüsTotalAPI = VT_API


    def VirusTotal_URL_Scanner(self, URLParams):
        print("Taranıyor : VirüsTotal URL Scanner !")
        print("Scanning URL : ", URLParams)


        # URL Scanner
        URL = "https://www.virustotal.com/api/v3/urls"
        PAYLAOD = {"url": URLParams}
        HEADERS = \
        {
            "accept": "application/json",
            "x-apikey": self.VirüsTotalAPI,
            "content-type": "application/x-www-form-urlencoded"
        }

        URLResponse = requests.post(URL, data=PAYLAOD, headers=HEADERS).json()
        URL_ID = URLResponse.get("data").get("id")



        #Report URL
        URL = f"https://www.virustotal.com/api/v3/analyses/{URL_ID}"
        ReportHeader = \
        {
            "accept": "application/json",
            "x-apikey": self.VirüsTotalAPI
        }

        Report = requests.get(URL, headers=ReportHeader).json().get("data").get("attributes").get("stats")

        if Report['malicious']:
            print("Kötü Niyetli URL.")

        elif Report['suspicious']:
            print("Şüpheli URL.")

        else:
            print(f"URL Temiz : {URLParams}")

        print("-----------------------------------------------\n")

    def VirüsTotal_DOMAIN_Scanner(self, DOMAIN):
        print("Taranıyor : VirüsTotal Domain Scanner.")
        print("Scanning Domain : ", DOMAIN)


        try:
            URL = f"https://www.virustotal.com/api/v3/domains/{DOMAIN}"

            DomainHeader = \
            {
                "accept": "application/json",
                "x-apikey": self.VirüsTotalAPI
            }

            DomainResponse = requests.get(URL, headers=DomainHeader).json()
            Report = DomainResponse.get("data").get("attributes").get("last_analysis_stats")

            if Report['malicious']:
                print("Kötü Niyetli Domain.")

            elif Report['suspicious']:
                print("Şüpheli Domain.")

            else:
                print(f"Domain Temiz : {DOMAIN}")
            print("-----------------------------------------------\n")
        except Exception as e:
            print(e)

    def VirüsTotal_FILE_Scanner(self, FILE):
        try:
            print("Taranıyor : VirüsTotal File Scanner.")
            print("Scanning File : ", FILE)


            # File Upload
            # ----------------------------------------------------------------------
            Files = {"file": (FILE, open(FILE, "rb"))}
            Headers = {"X-Apikey":self.VirüsTotalAPI}
            URL = "https://www.virustotal.com/api/v3/files"
            Upload_Response = requests.post(URL, files=Files, headers=Headers).json()
            ID = Upload_Response.get('data').get('id')


            # File Control

            ControlURL = f"https://www.virustotal.com/api/v3/analyses/{ID}"
            Headers = \
            {
                "accept": "application/json",
                "x-apikey": self.VirüsTotalAPI
            }

            ControlResponse = requests.get(ControlURL, headers=Headers).json()
            Malicious = ControlResponse.get("data").get("attributes").get("stats").get("malicious")
            Harmless = ControlResponse.get("data").get("attributes").get("stats").get("harmless")

            if Harmless > 0:
                print("Şüpheli Dosya Tespit Edildi.")
                print(f"Dosya : {FILE}\n")

            elif Malicious > 0:
                print("Tehlikeli Dosya Tespit Edildi.")
                print(f"Dosya : {FILE}\n")

            else:
                print(f"Dosya Temiz : {FILE}\n")
            print("-----------------------------------------------\n")
        except Exception as e:
            print(e)

    def VirüsTotal_IP_Scanner(self, IP):
        print("Tarama Tipi : VirüsTotal IP Scanner.")
        print("Scanning IP : ", IP)
        try:
            IPURL = f"https://www.virustotal.com/api/v3/ip_addresses/{IP}"

            IP_HEADERS = {
                "accept": "application/json",
                "x-apikey": self.VirüsTotalAPI
            }

            IPResponse = requests.get(IPURL, headers=IP_HEADERS).json()
            IPResponse = IPResponse.get("data").get("attributes").get("total_votes")

            if int(IPResponse['harmless']) != 0:
                print(f"Şüpheli IP Tespit Edildi : {IP}")

            elif int(IPResponse['malicious']) != 0:
                print(f"Zararlı IP Tespit Edildi : {IP}")

            else:
                print(f"IP Temiz : {IP}\n")


        except Exception as e:
            print(e)

VTTotal = VirüsTotal()

class Parser:

    def URLParse(self, URL):
        parseURL = urlparse(URL)
        return (URL, parseURL.hostname, parseURL.path, parseURL.scheme, parseURL.port, parseURL.query)

    def CotrolHTMLAttribute(self, HTMLCode):
        HTML_SRC_CODE = re.search(r'src="(.*?)"', HTMLCode)
        HTML_HREF_CODE = re.search(r'href="(.*?)"', HTMLCode)
        HTML_DATA_CODE = re.search(r'data="(.*?)"', HTMLCode)
        HTML_ACTİON_CODE = re.search(r'action="(.*?)"', HTMLCode)

        DictList = [".txt", ".csv", ".pdf", ".docx", ".xlsx", ".exe", ".zip"]

        if HTML_SRC_CODE != None:
            Parse_SRC = self.URLParse(HTML_SRC_CODE.group(1))

            if Parse_SRC[1] != None:

                if os.path.splitext(Parse_SRC[2])[1] in DictList:
                    HB_ANALYSİS.HybritAnalysis_SANDBOX_URL_SCANNER(Parse_SRC[0])
                    HB_ANALYSİS.HybritAnalysis_URL_SCANNER(Parse_SRC[0])
                    VTTotal.VirusTotal_URL_Scanner(URLParams=Parse_SRC[0])
                    VTTotal.VirüsTotal_DOMAIN_Scanner(DOMAIN=Parse_SRC[1])

                    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', Parse_SRC[1]) != None:
                        VTTotal.VirüsTotal_IP_Scanner(Parse_SRC[1])
                    print("-----------------------------------------------\n")

                else:
                    VTTotal.VirusTotal_URL_Scanner(URLParams=Parse_SRC[0])
                    VTTotal.VirüsTotal_DOMAIN_Scanner(DOMAIN=Parse_SRC[1])
                    HB_ANALYSİS.HybritAnalysis_URL_SCANNER(Parse_SRC[0])
                    HB_ANALYSİS.HybritAnalysis_SANDBOX_URL_SCANNER(Parse_SRC[0])

                    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', Parse_SRC[1]) != None:
                        VTTotal.VirüsTotal_IP_Scanner(Parse_SRC[1])

            else:
                VTTotal.VirüsTotal_FILE_Scanner(FILE=Parse_SRC[0])
                HB_ANALYSİS.HybritAnalysis_FILE_SCANNER(Parse_SRC[0])
                HB_ANALYSİS.HybritAnalysis_SANDBOX_FILE_SCANNER(Parse_SRC[0])

        elif HTML_HREF_CODE != None:
            Parse_SRC = self.URLParse(HTML_HREF_CODE.group(1))

            if Parse_SRC[1] != None:

                if os.path.splitext(Parse_SRC[2])[1] in DictList:
                    print("Uyarı URL Bir Dosya Barındırıyor.")
                    print("İndirdiğiniz Dosyayı Virüs Taraması Yapmadan Kullanmayınız.")
                    print("URL : ", Parse_SRC[0])
                    print("-----------------------------------------------\n")

                else:
                    VTTotal.VirusTotal_URL_Scanner(URLParams=Parse_SRC[0])
                    VTTotal.VirüsTotal_DOMAIN_Scanner(DOMAIN=Parse_SRC[1])

            else:
                VTTotal.VirüsTotal_FILE_Scanner(FILE=Parse_SRC[0])

        elif HTML_DATA_CODE != None:
            Parse_SRC = self.URLParse(HTML_DATA_CODE.group(1))

            if Parse_SRC[1] != None:

                if os.path.splitext(Parse_SRC[2])[1] in DictList:
                    print("Uyarı URL Bir Dosya Barındırıyor.")
                    print("İndirdiğiniz Dosyayı Virüs Taraması Yapmadan Kullanmayınız.")
                    print("URL : ", Parse_SRC[0])
                    print("-----------------------------------------------\n")

                else:
                    VTTotal.VirusTotal_URL_Scanner(URLParams=Parse_SRC[0])
                    VTTotal.VirüsTotal_DOMAIN_Scanner(DOMAIN=Parse_SRC[1])

            else:
                VTTotal.VirüsTotal_FILE_Scanner(FILE=Parse_SRC[0])

        elif HTML_ACTİON_CODE != None:
            Parse_SRC = self.URLParse(HTML_ACTİON_CODE.group(1))

            if Parse_SRC[1] != None:

                if os.path.splitext(Parse_SRC[2])[1] in DictList:
                    print("Uyarı URL Bir Dosya Barındırıyor.")
                    print("İndirdiğiniz Dosyayı Virüs Taraması Yapmadan Kullanmayınız.")
                    print("URL : ", Parse_SRC[0])
                    print("-----------------------------------------------\n")

                else:
                    VTTotal.VirusTotal_URL_Scanner(URLParams=Parse_SRC[0])
                    VTTotal.VirüsTotal_DOMAIN_Scanner(DOMAIN=Parse_SRC[1])

            else:
                VTTotal.VirüsTotal_FILE_Scanner(FILE=Parse_SRC[0])

class FileManager:
    def setFile(self, NewFile): self.File = NewFile
    def getFile(self): return self.File
    def getName(self): return str(os.path.splitext(self.File)[0])
    def getSize(self): return str(float(os.path.getsize(self.File) / 1000))
    def getSplitName(self): return str(os.path.splitext(self.File)[1])
    def getTime_C(self): return str(os.path.getctime(self.File))
    def getTime_M(self): return str(os.path.getmtime(self.File))
    def getTime_A(self): return str(time.ctime(os.path.getatime(self.File)))
    def getReadlines(self, File, Mod):
        with open(File, 'r') as file:

            if Mod == "File":
                return enumerate([i for i in file.readlines()]);

            elif Mod == "Live":
                return enumerate([i.replace(r"\n", "").strip() for i in file.readlines() if i.strip() != ""]);
    def getRead(self, File):
        with open(File, "r") as file:
            return file.read()

    def __init__(self):
        self.File = FILES

class Scanner:
    def __init__(self):
        self.VirüsTotal = VirüsTotal()
        self.HybritAnalysis = HybritAnalysis()
        self.File = FileManager()
        self.Parse = Parser()


        self.AddLog = deque(maxlen=200)
        self.RemoveLog = deque(maxlen=200)



        #self.LiveScannerProcess = threading.Thread(target=self.LiveScannerFile, daemon=False)
        #self.LiveScannerProcess.start()

        self.FileScannerProcess = threading.Thread(target=self.FileScanner, daemon=False)
        self.FileScannerProcess.start()



    def FileScanner(self):
        "Dosya Tabanlı Tarama, Seçilen Dosyayı Tüm Satırlarını Tarar ve Gerekli Filtreleme Fonksiyonlarına Gönderir."

        Second = 0
        ThreadStart = True


        while True:
            Second += 5

            #İlk Tarama

            if ThreadStart:
                ThreadStart = False

                self.VirüsTotal.VirüsTotal_FILE_Scanner(self.File.getFile())
                self.HybritAnalysis.HybritAnalysis_SANDBOX_FILE_SCANNER(self.File.getFile())
                self.HybritAnalysis.HybritAnalysis_FILE_SCANNER(self.File.getFile())

                for i in self.File.getReadlines(File=self.File.getFile(), Mod="Live"):
                    self.Parse.CotrolHTMLAttribute(i[1])


            if Second == 600:
                Second -= 600
                print("S2ş")
                exit()
                self.VirüsTotal.VirüsTotal_FILE_Scanner(self.File.getFile())


            for i in self.File.getReadlines(File=self.File.getFile(), Mod="Live"):
                self.Parse.CotrolHTMLAttribute(i[1])

            time.sleep(5)

    def LiveScanner(self):
        "Canlı İzleme Tabanlı Tarama, Seçilen Dosyayı Anlık Olarak İzler Ve Değişiklikleri Tarar."

        SonDeğiştirmeZamanı = self.getTime_M()
        SonBoyut = self.getSize()
        SonSatırlar = [i[1] for i in self.getReadlines(self.getFile(), Mod="Live")]


        while True:
            time.sleep(3)


            try:
                # Dosya Boyutu veya Son Değiştirme Tarihi Kontrol Sistemi
                if self.getTime_M() != SonDeğiştirmeZamanı or self.getSize() != SonBoyut:
                    SonDeğiştirmeZamanı = self.getTime_M()
                    SonBoyut = self.getSize()



                    NewLines = [i[1] for i in self.getReadlines(self.getFile(), Mod="Live")] # Anlık Satırları Getirir.

                    DifferenceLinesNegatif = [x for x in SonSatırlar if x not in NewLines] # Silinenleri Verir.
                    DifferenceLinesPozitif = [y for y in NewLines if y not in SonSatırlar] # Eklenenleri Verir.

                    SonSatırlar = NewLines # Son Satırları Yeniyle Güncellendi


                    if len(DifferenceLinesNegatif) > 0:
                        self.RemoveLog.append(DifferenceLinesNegatif) # Silinen Verilerin Logları Tutuldu.
                        print("Silindi : ", DifferenceLinesNegatif)

                    if len(DifferenceLinesPozitif) > 0:
                        self.AddLog.append(DifferenceLinesPozitif)  # Yeni Eklenen Verilerin Logları Tutuldu.
                        print("Eklendi : ", DifferenceLinesPozitif)


                        #for i in DifferenceLinesPozitif:
                            #self.CotrolHTMLAttribute(i)

            except Exception as e:
                print(e)



if __name__ == "__main__":
    OneDayEnginner = Scanner()
