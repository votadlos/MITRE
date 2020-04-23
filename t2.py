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

def get_color(score, d):
	if d == ['N/A']:
		return "#DF01D7" #violet
	if score <10:
		return "#FE2E2E" #red
	if score <35:
		return "#F7FE2E" #yellow
	if score <70:
		return "#40FF00" #light green
	if score >=70:
		return "#31B404" #green

def print_screenshots(a):
	ret = ''
	i = 1
	for s in a:
		ret += '  <a href="https://d1zq5d3dtjfcoj.cloudfront.net/' + s.get("ScreenshotName","") + '" target="_blank"><small> Screenshot' + str(i) + '</small></a>'
		i += 1
	return ret


a = {
	"N/A":0,
	"None":0,
	"Telemetry":10,
	"General":30,
	"Tactic":40, #not clear with General, but think it's better
	"Technique":60,
	"MSSP":70,

	"Alert":5,
	"Correlated":7,
	"Delayed (Manual)":0,
	"Delayed (Processing)":0,
	"Residual Artifact":0,
	"Host Interrogation":3,
	"Configuration Change":-7,
	"Configuration Change (Detections)":-7,
	"Configuration Change (UX)":-7,
	"Innovative":8
}
vendors = dict()
res = dict()
unique_detect_types = ['N/A','None','Telemetry','General','Tactic','Technique','MSSP']

for j in glob.glob("./evals/*.APT29.1_Results.json"):
	v = j[8:-23] #./evals/Kaspersky.1.APT29.1_Results.json
	print "DEBUG:", j,v
	vendors[v] = dict()
	vendors[v]["Total Score"] = 0

	d = dict()
	with open(j) as f:
		d = json.load(f)
	for t in d["Techniques"]: #technique
		#print "\tTechnique: ", t["TechniqueId"]
		if res.get(t["TechniqueId"],"IhatePython") == "IhatePython":
			res[t["TechniqueId"]] = dict()
		res[t["TechniqueId"]]["TechniqueName"] = t["TechniqueName"]
		res[t["TechniqueId"]]["Tactics"] = t["Tactics"]

		if res[t["TechniqueId"]].get("Steps","IhatePython") == "IhatePython":
			res[t["TechniqueId"]]["Steps"] = dict()

		steps_count = 0
		for s in t["Steps"]: #Steps
			#print "\t\tStep: ",s["SubStep"]
			if res[t["TechniqueId"]]["Steps"].get(s["SubStep"], "IhatePython") == "IhatePython":
				res[t["TechniqueId"]]["Steps"][s["SubStep"]] = dict()
			steps_count += 1
			res[t["TechniqueId"]]["Steps"][s["SubStep"]]["Procedure"] = s["Procedure"]


			if res[t["TechniqueId"]]["Steps"][s["SubStep"]].get(v,"IhatePython") == "IhatePython":
				res[t["TechniqueId"]]["Steps"][s["SubStep"]][v] = dict()
			res[t["TechniqueId"]]["Steps"][s["SubStep"]][v]["Detects"] = list()

			res[t["TechniqueId"]]["Steps"][s["SubStep"]][v]["Step score"] = 0
			for det in s["Detections"]: #Detectors for technique on particular step
				if vendors[v].get("Detects", None) == None:
					vendors[v]["Detects"] = dict()
				vendors[v]["Detects"][det["DetectionType"]] = vendors[v]["Detects"].get(det["DetectionType"],0) + 1
				#unique_detect_types[det["DetectionType"]] = unique_detect_types.get(det["DetectionType"],0) + 1
				res[t["TechniqueId"]]["Steps"][s["SubStep"]][v]["Step score"] += a[det["DetectionType"]]
				det_score = a[det["DetectionType"]]
				for mm in det["Modifiers"]:
					det_score += a[mm]
					res[t["TechniqueId"]]["Steps"][s["SubStep"]][v]["Step score"] += a[mm]
				dd = dict()
				dd["Detect"] = u'-'.join([det["DetectionType"]] + det["Modifiers"])

				dd["Screenshots"] = det.get("Screenshots",[])
				dd["DetectionNote"] = det["DetectionNote"]
				dd["Score"] = det_score
				res[t["TechniqueId"]]["Steps"][s["SubStep"]][v]["Detects"].append(dd)

			vendors[v]["Total Score"] += res[t["TechniqueId"]]["Steps"][s["SubStep"]][v]["Step score"]

			if steps_count > res[t["TechniqueId"]].get("Steps count",0):
				res[t["TechniqueId"]]["Steps count"] = steps_count

	#print "DEBUG:", v,"- done"


with open("out2.json", "w") as ff:
	json.dump(res, ff)

f = open("out2.html", "w")
f.write("<html><body><table border=\"1\" cellspacing=\"0\"><tr><th>"+u"</th><th>".join(["Technique", "Step", "Procedures"])+u"</th><th colspan=\"2\">"+"</th><th colspan=\"2\">".join(sorted(vendors.keys()))+"</th></tr>")
for t in res.keys(): #TechniqueId
	f.write('<tr><td rowspan="'+str(res[t]["Steps count"])+'"><b>'+res[t]["TechniqueName"]
		+ "</b><br><br><i>"+ u"<br>".join( u": ".join([u'<a href="https://attack.mitre.org/tactics/'+x["TacticId"]+'/" target="_blank">'+x["TacticId"]+u"</a>",x["TacticName"]]) for x in res[t]["Tactics"])
		+ '</i><br><br>(<a href="https://attack.mitre.org/techniques/' + t + '/" target="_blank">' + t + "</a>)</td>")
	flag = 0
	for s in res[t]["Steps"]: #SubStep
		if flag > 0:
			f.write("<tr>")
		f.write("<td>" + s + "</td><td>" + res[t]["Steps"][s]["Procedure"] + "</td>")
		for v in sorted(vendors.keys()):
			if res[t]["Steps"][s].get(v, "IhatePython") == "IhatePython":
				res[t]["Steps"][s][v] = dict()
				res[t]["Steps"][s][v]["Detects"] = ['N/A']
				res[t]["Steps"][s][v]["Screenshots"] = [{"":""}]
				res[t]["Steps"][s][v]["Step score"] = 0
			bgcolor = get_color(res[t]["Steps"][s][v]["Step score"],res[t]["Steps"][s][v]["Detects"])
			f.write(u"<td><p>" + u"</p><p>".join(x["DetectionNote"]+"<br>"+print_screenshots(x.get("Screenshots",[{"":""}])) for x in res[t]["Steps"][s][v]["Detects"])
				+ u"</p></td><td align=\"center\" bgcolor=\""+bgcolor+"\">"
				+ u"<p>" + u"</p><p>".join( x["Detect"]+"("+str(x["Score"])+")" for x in res[t]["Steps"][s][v]["Detects"]) + u"</p>"
				+ u"<h3>"+str(res[t]["Steps"][s][v]["Step score"]) + u"</h3></td>")
		f.write("</tr>")
		flag += 1
	f.write("<tr><td align=\"center\" bgcolor=\"#000000\">"+u"</td><td align=\"center\" bgcolor=\"#000000\">".join(["<font color=\"#FFFFFF\">Technique</font>", "<font color=\"#FFFFFF\">Step</font>", "<font color=\"#FFFFFF\">Procedures</font>"])+u"</td><td align=\"center\" colspan=\"2\" bgcolor=\"#000000\" >"+"</td><td align=\"center\" colspan=\"2\" bgcolor=\"#000000\" >".join(map(lambda x: "<font color=\"#FFFFFF\">"+x+"</font>",sorted(vendors.keys())))+"</td></tr>")
f.write("<tr><td colspan=\"3\"><p><br><h3>TOTAL SCORE</h3></p></td><td align=\"right\" colspan=\"2\">" + u"</p></td><td align=\"right\" colspan=\"2\">".join([u"<p><br><h3>"+str(vendors[x]["Total Score"])+u"</h3></p>"for x in sorted(vendors.keys()) ]) + u"</td></tr>"  )
f.write("</table></body></html>")
f.close()


#for v in sorted(vendors.keys()):
#	print(v,":",vendors[v]["Detects"])
#print(unique_detect_types)

f = open("out2-combined.html", "w")
f.write(u"<html><body><table border=\"1\" cellspacing=\"0\"><tr><th rowspan=\"2\">Vendors</th><th colspan=\"2\">" + u"</th><th colspan=\"2\">".join(unique_detect_types) + u"</th><th rowspan=\"2\">Sum points</th></tr>" \
	+u"<tr><th>" + u"</th><th>".join(["Count</th><th>Points" for x in unique_detect_types]) )
[ f.write(u'<tr><td><a href="https://attackevals.mitre.org/APT29/results/'+v.lower()+'/" target="_blank"><b>'+v+u"</b></a></td><td>"+u"</td><td>".join([str(vendors[v]["Detects"].get(x," ")) +u"</td><td>"+ str(vendors[v]["Detects"].get(x,0)*a[x]) for x in unique_detect_types])+u"</td><td>"+str(vendors[v]["Total Score"])+u"</td><tr>") for v in sorted(vendors.keys()) ]
f.write("</table></body></html>")
f.close()
