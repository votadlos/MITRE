#!/usr/bin/python
#
# Compare EDR solution based on MITRE's evaluation: https://attackevals.mitre.org/evaluations.html
# Sergey Soldatov, 2018-12-01
#
# Usage: when started it takes all *.1.APT3.1_Results.json files in current directore and produces out.html
#

import glob, json, sys, re
reload(sys)
sys.setdefaultencoding('utf8')

def get_color(score):
	if score <10:
		return "#FE2E2E" #red
	if score <=29:
		return "#F7FE2E" #yellow
	if score <60:
		return "#40FF00" #light green
	if score >=60:
		return "#31B404" #green

def print_screenshots(h):
	ret = ''
	for k in h.keys():
		if len(k) > 0:
			ret += '<p><a href="https://d1zq5d3dtjfcoj.cloudfront.net/' + k + '" target="_blank"><small>'+h[k]+'</small></a></p>'
	return ret

res = dict()
a = {
	"None":0,
	"Telemetry":10,
	"Enrichment":15,
	"Indicator of Compromise":20,
	"General Behavior":30,
	"Specific Behavior":60,
	"Delayed":-3,
	"Tainted":-3,
	"Configuration Change":-3
}
vendors = dict()

for j in glob.glob("./evals/*.1.APT3.1_Results.json"):
	v = j[8:-22]
	#print "DEBUG:", j,v
	vendors[v] = dict()
	vendors[v]["Total Score"] = 0

	d = dict()
	with open(j) as f:
		d = json.load(f)
	for t in d.keys(): #techniques
		if re.match(r'^T\d+$',t):
			#print "\tTechnique: ",t
			if res.get(t,"IhatePython") == "IhatePython":
				res[t] = dict()
			res[t]["TechniqueName"] = d[t]["TechniqueName"]
			res[t]["TacticGroup"] = d[t]["TacticGroup"]
			if res[t].get("Steps","IhatePython") == "IhatePython":
				res[t]["Steps"] = dict()

			steps_count = 0
			for s in d[t]["Steps"].keys(): #Steps
				#print "\t\tStep: ",s
				if res[t]["Steps"].get(s, "IhatePython") == "IhatePython":
					res[t]["Steps"][s] = dict()
				steps_count += 1
				res[t]["Steps"][s]["Procedure"] = d[t]["Steps"][s]["Procedure"]
				score = 0;
				if res[t]["Steps"][s].get(v,"IhatePython") == "IhatePython":
					res[t]["Steps"][s][v] = dict()
				res[t]["Steps"][s][v]["Detects"] = list()
				for i in xrange(len(d[t]["Steps"][s]["DetectionCategories"])): #Detectors for technique on particular step
					detects = []
					for det in map(lambda x: x.strip(), d[t]["Steps"][s]["DetectionCategories"][i].keys()[0].split(',')): #Detections and Modifiers
						if len(det) == 0:
							det = "None"
						score += a[det]
						detects.append(det)
					res[t]["Steps"][s][v]["Detects"].append(u'-'.join(detects))
					res[t]["Steps"][s][v]["Screenshots"] = d[t]["Steps"][s]["Screenshots"]
				res[t]["Steps"][s][v]["Score"] = score
				vendors[v]["Total Score"] += score

			if steps_count > res[t].get("Steps count",0):
				res[t]["Steps count"] = steps_count

	#print "DEBUG:", v,"- done"

with open("out.json", "w") as ff:
	json.dump(res, ff)

f = open("out.html", "w")
f.write("<html><body><table border=\"1\" cellspacing=\"0\"><tr><th>"+u"</th><th>".join(["Technique", "Step", "Procedures"])+u"</th><th colspan=\"2\">"+"</th><th colspan=\"2\">".join(sorted(vendors.keys()))+"</th></tr>")
for t in res.keys():
	f.write("<tr><td rowspan=\""+str(res[t]["Steps count"])+"\"><b>"+res[t]["TechniqueName"]+"</b><br><br><i>"+res[t]["TacticGroup"]+"</i><br><br>(<a href=\"https://attack.mitre.org/techniques/"+t+"/\">"+t+"</a>)</td>")
	flag = 0
	for s in res[t]["Steps"]:
		if flag > 0:
			f.write("<tr>")
		f.write("<td>"+s+"</td><td>"+res[t]["Steps"][s]["Procedure"]+"</td>")
		for v in sorted(vendors.keys()):
			if res[t]["Steps"][s].get(v, "IhatePython") == "IhatePython":
				bgcolor = "#DF01D7"
				res[t]["Steps"][s][v] = dict()
				res[t]["Steps"][s][v]["Detects"] = ['Not tested']
				res[t]["Steps"][s][v]["Screenshots"] = {"":""}
				res[t]["Steps"][s][v]["Score"] = 0
			else:
				bgcolor = get_color(res[t]["Steps"][s][v]["Score"])
			f.write("<td>"+print_screenshots(res[t]["Steps"][s][v]["Screenshots"])+"</td><td align=\"center\" bgcolor=\""+bgcolor+"\">"+"<p>"+u"</p><p>".join(res[t]["Steps"][s][v]["Detects"])+"</p>"+str(res[t]["Steps"][s][v]["Score"])+"</td>")
		f.write("</tr>")
		flag += 1
	f.write("<tr><td align=\"center\" bgcolor=\"#000000\">"+u"</td><td align=\"center\" bgcolor=\"#000000\">".join(["<font color=\"#FFFFFF\">Technique</font>", "<font color=\"#FFFFFF\">Step</font>", "<font color=\"#FFFFFF\">Procedures</font>"])+u"</td><td align=\"center\" colspan=\"2\" bgcolor=\"#000000\" >"+"</td><td align=\"center\" colspan=\"2\" bgcolor=\"#000000\" >".join(map(lambda x: "<font color=\"#FFFFFF\">"+x+"</font>",sorted(vendors.keys())))+"</td></tr>")
f.write("<tr><td colspan=\"3\"><b>TOTAL SCORE</b></td><td align=\"right\" colspan=\"2\"><b>"+u"</td><td align=\"right\" colspan=\"2\"><b>".join( map(lambda x: str(vendors[x]["Total Score"]), sorted(vendors.keys())) )+"</td></tr>"  )
f.write("</table></body></html>")
f.close()
