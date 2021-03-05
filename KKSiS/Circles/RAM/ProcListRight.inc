; ---- Process Measure ----

[Measure_Top1]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=1
UpdateDivider		=1

[Measure_Top2]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=2
UpdateDivider		=1

[Measure_Top3]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=3
UpdateDivider		=1

[Measure_Top4]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=4
UpdateDivider		=1

[Measure_Top5]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=5
UpdateDivider		=1

[Measure_Top6]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=6
UpdateDivider		=1

[Measure_Top7]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=7
UpdateDivider		=1

[Measure_Top8]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=8
UpdateDivider		=1

[Measure_Top9]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=9
UpdateDivider		=1

[Measure_Top10]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=RAM
Index				=10
UpdateDivider		=1

; ---- Process List ----

[Process_1Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.02)
	Text=[Measure_Top1:/1048576,0] MB
[Process_1Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top1]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_2Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top2:/1048576,0] MB
[Process_2Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top2]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_3Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top3:/1048576,0] MB
[Process_3Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top3]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_4Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top4:/1048576,0] MB
[Process_4Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top4]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_5Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top5:/1048576,0] MB
[Process_5Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top5]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_6Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top6:/1048576,0] MB
[Process_6Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top6]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_7Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top7:/1048576,0] MB
[Process_7Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top7]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_8Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top8:/1048576,0] MB
[Process_8Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top8]
	Clipstring=1
	W=(#CRadius#*1.25)
	
[Process_9Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top9:/1048576,0] MB
[Process_9Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top9]
	Clipstring=1
	W=(#CRadius#*1.25)

[Process_10Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top10:/1048576,0] MB
[Process_10Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.60)r
	Y=0r
	Text=[Measure_Top8]
	Clipstring=1
	W=(#CRadius#*1.25)