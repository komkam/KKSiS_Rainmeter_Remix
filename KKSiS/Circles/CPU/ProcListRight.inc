; ---- Process Measure ----

[Measure_Top1]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=1
IfCondition			=(Measure_Top1 >= 0.01)
IfTrueAction		=[!ShowMeter Process_1Percent][!ShowMeter Process_1Name]
IfFalseAction		=[!HideMeter Process_1Percent][!HideMeter Process_1Name]
UpdateDivider		=1

[Measure_Top2]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=2
IfCondition			=(Measure_Top2 >= 0.01)
IfTrueAction		=[!ShowMeter Process_2Percent][!ShowMeter Process_2Name]
IfFalseAction		=[!HideMeter Process_2Percent][!HideMeter Process_2Name]
UpdateDivider		=1

[Measure_Top3]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=3
IfCondition			=(Measure_Top3 >= 0.01)
IfTrueAction		=[!ShowMeter Process_3Percent][!ShowMeter Process_3Name]
IfFalseAction		=[!HideMeter Process_3Percent][!HideMeter Process_3Name]
UpdateDivider		=1

[Measure_Top4]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=4
IfCondition			=(Measure_Top4 >= 0.01)
IfTrueAction		=[!ShowMeter Process_4Percent][!ShowMeter Process_4Name]
IfFalseAction		=[!HideMeter Process_4Percent][!HideMeter Process_4Name]
UpdateDivider		=1

[Measure_Top5]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=5
IfCondition			=(Measure_Top5 >= 0.01)
IfTrueAction		=[!ShowMeter Process_5Percent][!ShowMeter Process_5Name]
IfFalseAction		=[!HideMeter Process_5Percent][!HideMeter Process_5Name]
UpdateDivider		=1

[Measure_Top6]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=6
IfCondition			=(Measure_Top6 >= 0.01)
IfTrueAction		=[!ShowMeter Process_6Percent][!ShowMeter Process_6Name]
IfFalseAction		=[!HideMeter Process_6Percent][!HideMeter Process_6Name]
UpdateDivider		=1

[Measure_Top7]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=7
IfCondition			=(Measure_Top7 >= 0.01)
IfTrueAction		=[!ShowMeter Process_7Percent][!ShowMeter Process_7Name]
IfFalseAction		=[!HideMeter Process_7Percent][!HideMeter Process_7Name]
UpdateDivider		=1

[Measure_Top8]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=8
IfCondition			=(Measure_Top8 >= 0.01)
IfTrueAction		=[!ShowMeter Process_8Percent][!ShowMeter Process_8Name]
IfFalseAction		=[!HideMeter Process_8Percent][!HideMeter Process_8Name]
UpdateDivider		=1

[Measure_Top9]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=9
IfCondition			=(Measure_Top9 >= 0.01)
IfTrueAction		=[!ShowMeter Process_9Percent][!ShowMeter Process_9Name]
IfFalseAction		=[!HideMeter Process_9Percent][!HideMeter Process_9Name]
UpdateDivider		=1

[Measure_Top10]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=10
IfCondition			=(Measure_Top10 >= 0.01)
IfTrueAction		=[!ShowMeter Process_10Percent][!ShowMeter Process_10Name]
IfFalseAction		=[!HideMeter Process_10Percent][!HideMeter Process_10Name]
UpdateDivider		=1

; ---- Process List ----

[Process_1Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.02)
	Text=[Measure_Top1:2]%
	Hidden=1
[Process_1Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top1]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_2Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top2:2]%
	Hidden=1
[Process_2Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top2]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_3Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top3:2]%
	Hidden=1
[Process_3Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top3]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_4Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top4:2]%
	Hidden=1
[Process_4Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top4]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_5Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top5:2]%
	Hidden=1
[Process_5Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top5]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_6Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top6:2]%
	Hidden=1
[Process_6Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top6]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_7Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top7:2]%
	Hidden=1
[Process_7Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top7]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_8Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top8:2]%
	Hidden=1
[Process_8Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top8]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1
	
[Process_9Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top9:2]%
	Hidden=1
[Process_9Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top9]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1

[Process_10Percent]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Left
	X=(#CRadius#*2.00)
	Y=(#CRadius#*0.15)r
	Text=[Measure_Top8:2]%
	Hidden=1
[Process_10Name]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.55)r
	Y=0r
	Text=[Measure_Top8]
	Clipstring=1
	W=(#CRadius#*1.25)
	Hidden=1