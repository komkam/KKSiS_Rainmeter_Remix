[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc


;---- Measures ----

[TimeSeconds]
Measure=Time
Format=%S
UpdateDivider=1

[DateYear]
Measure=Time
Format=%Y
UpdateDivider=60

[DateMonth]
Measure=Time
Format=%m
UpdateDivider=60

[DateDay]
Measure=Time
Format=%d
UpdateDivider=1
DynamicVariables=1

[TimeHours24H]
Measure=Time
Format=%H

[TimeHours12H]
Measure=Time
Format=%I

[TimeMinutes]
Measure=Time
Format=%M

[TimeAMPM]
Measure=Time
Format=%p
UpdateDivider=10

[DateWeek]
Measure=Time
Format=%V
UpdateDivider=10

[DateWeek2]
Measure=Time
Format=%U
UpdateDivider=10

[DateWeekNo]
Measure=Time
Format=%#w
UpdateDivider=10


;---- Week ----

[WeekdaymarkerNonColored]
Meter=Shape
Shape=Rectangle (#PHeight#*0.38),(#PHeight#*0.375),(#PHeight#*0.28),(#PHeight#*0.12),(#PHeight#*0.01) | Fill Color 0,0,0,0 | StrokeWidth (#PHeight#*0.012) | Stroke Color #Panel-FontColor#
DynamicVariables=1
Group=Weekday
Hidden=1
DynamicVariables=1

[WeekdaymarkerColored]
Meter=Shape
Shape=Rectangle (#PHeight#*0.38),(#PHeight#*0.375),(#PHeight#*0.28),(#PHeight#*0.12),(#PHeight#*0.01) | Fill Color 0,0,0,0 | StrokeWidth (#PHeight#*0.012) | Stroke Color #Panel-BarFillColor1#
DynamicVariables=1
Group=Weekday
Hidden=0

[WeekDay1]
Meter=String
MeterStyle=PText | PSize8
StringAlign=Left
X=(#PHeight#*0.73)
Y=(#PHeight#*0.11)
Text=2
DynamicVariables=1
Group=Weekday

[WeekDay2]
Meter=String
MeterStyle=PText | PSize7
StringAlign=Left
X=(#PHeight#*0.655)
Y=(#PHeight#*0.18)
Text=2
DynamicVariables=1
Group=Weekday

[WeekDay3]
Meter=String
MeterStyle=PText | PSize6
StringAlign=Left
X=(#PHeight#*0.58)
Y=(#PHeight#*0.255)
Text=3
DynamicVariables=1
Group=Weekday

[WeekDay4]
Meter=String
MeterStyle=PText | PSize4
StringAlign=Center
X=(#PHeight#*0.52)
Y=(#PHeight#*0.36)
Text=4
DynamicVariables=1
Group=Weekday

[WeekDay5]
Meter=String
MeterStyle=PText | PSize6
StringAlign=Left
X=(#PHeight#*0.335)
Y=(#PHeight#*0.5)
Text=5
DynamicVariables=1
Group=Weekday

[WeekDay6]
Meter=String
MeterStyle=PText | PSize7
StringAlign=Left
X=(#PHeight#*0.25)
Y=(#PHeight#*0.59)
Text=6
DynamicVariables=1
Group=Weekday

[WeekDay7]
Meter=String
MeterStyle=PText | PSize8
StringAlign=Left
X=(#PHeight#*0.175)
Y=(#PHeight#*0.67)
Text=7
DynamicVariables=1
Group=Weekday

[WeekDay]
Measure=Calc
Formula=DateWeekNo
IfCondition=WeekDay = 0
IfTrueAction=[!SetOption WeekDay1 Text #TIWD3#][!SetOption WeekDay2 Text #TIWD2#][!SetOption WeekDay3 Text #TIWD1#][!SetOption WeekDay4 Text #TIWD0#][!SetOption WeekDay5 Text #TIWD6#][!SetOption WeekDay6 Text #TIWD5#][!SetOption WeekDay7 Text #TIWD4#]
IfCondition2=WeekDay = 1
IfTrueAction2=[!SetOption WeekDay1 Text #TIWD4#][!SetOption WeekDay2 Text #TIWD3#][!SetOption WeekDay3 Text #TIWD2#][!SetOption WeekDay4 Text #TIWD1#][!SetOption WeekDay5 Text #TIWD0#][!SetOption WeekDay6 Text #TIWD6#][!SetOption WeekDay7 Text #TIWD5#]
IfCondition3=WeekDay = 2
IfTrueAction3=[!SetOption WeekDay1 Text #TIWD5#][!SetOption WeekDay2 Text #TIWD4#][!SetOption WeekDay3 Text #TIWD3#][!SetOption WeekDay4 Text #TIWD2#][!SetOption WeekDay5 Text #TIWD1#][!SetOption WeekDay6 Text #TIWD0#][!SetOption WeekDay7 Text #TIWD6#]
IfCondition4=WeekDay = 3
IfTrueAction4=[!SetOption WeekDay1 Text #TIWD6#][!SetOption WeekDay2 Text #TIWD5#][!SetOption WeekDay3 Text #TIWD4#][!SetOption WeekDay4 Text #TIWD3#][!SetOption WeekDay5 Text #TIWD2#][!SetOption WeekDay6 Text #TIWD1#][!SetOption WeekDay7 Text #TIWD0#]
IfCondition5=WeekDay = 4
IfTrueAction5=[!SetOption WeekDay1 Text #TIWD0#][!SetOption WeekDay2 Text #TIWD6#][!SetOption WeekDay3 Text #TIWD5#][!SetOption WeekDay4 Text #TIWD4#][!SetOption WeekDay5 Text #TIWD3#][!SetOption WeekDay6 Text #TIWD2#][!SetOption WeekDay7 Text #TIWD1#]
IfCondition6=WeekDay = 5
IfTrueAction6=[!SetOption WeekDay1 Text #TIWD1#][!SetOption WeekDay2 Text #TIWD0#][!SetOption WeekDay3 Text #TIWD6#][!SetOption WeekDay4 Text #TIWD5#][!SetOption WeekDay5 Text #TIWD4#][!SetOption WeekDay6 Text #TIWD3#][!SetOption WeekDay7 Text #TIWD2#]
IfCondition7=WeekDay = 6
IfTrueAction7=[!SetOption WeekDay1 Text #TIWD2#][!SetOption WeekDay2 Text #TIWD1#][!SetOption WeekDay3 Text #TIWD0#][!SetOption WeekDay4 Text #TIWD6#][!SetOption WeekDay5 Text #TIWD5#][!SetOption WeekDay6 Text #TIWD4#][!SetOption WeekDay7 Text #TIWD3#]
UpdateDivider=10

[CurrentDateEN]
Meter=String
MeasureName=DateDay
MeasureName2=DateMonth
MeasureName3=DateYear
MeterStyle=PText | PSize5
Text=%2-%1-%3
Hidden=1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.04)
Group=english

[CurrentDateDE]
Meter=String
MeasureName=DateDay
MeasureName2=DateMonth
MeasureName3=DateYear
MeterStyle=PText | PSize5
Text=%1.%2.%3
Hidden=0
X=(#PHeight#*0.08)
Y=(#PHeight#*0.04)
Group=german

[CurrentTime24h]
Meter=String
MeasureName=TimeHours24H
MeasureName2=TimeMinutes
MeterStyle=PText | PSize0
Text=%1:%2
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.64)
Group=24h
Hidden=0

[CurrentTime12h]
Meter=String
MeasureName=TimeHours12H
MeasureName2=TimeMinutes
MeterStyle=PText | PSize0
Text=%1:%2
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.64)
Group=12h
Hidden=1

[CurrentSecs]
Meter=String
MeasureName=TimeSeconds
MeterStyle=PText | PSize5
Text=%1
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.56)
Hidden=#TIHideSeconds#

[CurrentAMPM]
Meter=String
MeasureName=TimeAMPM
MeterStyle=PText | PSize5
Text=%1
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.88)
Group=12H
Hidden=1

[CurrentWeekISO8601]
Meter=String
MeasureName=DateWeek
MeterStyle=PText | PSize5
StringAlign=Left
Text=#TIWeek# %1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.14)
Hidden=0

[CurrentWeek]
Meter=String
MeasureName=DateWeek2
MeterStyle=PText | PSize5
StringAlign=Left
Text=#TIWeek# %1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.14)
Hidden=1


;---- Skin Functions ----

[TimeFormat]
Measure=String
String=#Panel-TIFormat#
IfMatch=12H
IfMatchAction=[!HideMeterGroup "24H"][!ShowMeterGroup "12H"]
IfMatch2=24H
IfMatchAction2=[!HideMeterGroup "12H"][!ShowMeterGroup "24H"]
UpdateDivier=-1

[LanguageFormat]
Measure=String
String=#Panel-Language#
IfMatch=german
IfMatchAction=[!HideMeterGroup "english"][!ShowMeterGroup "german"]
IfMatch2=english
IfMatchAction2=[!HideMeterGroup "german"][!ShowMeterGroup "english"]
UpdateDivier=-1

[CWeekFormat]
Measure=String
String=#TIShowCWIsoFormat#
IfMatch=1
IfMatchAction=[!HideMeter "CurrentWeek"][!ShowMeter "CurrentWeekISO8601"]
IfMatch2=0
IfMatchAction2=[!HideMeter "CurrentWeekISO8601"][!ShowMeter "CurrentWeek"]
UpdateDivier=-1

[WeekdayMarkerFormat]
Measure=String
String=#TIShowColoredWeekday#
IfMatch=1
IfMatchAction=[!HideMeter "WeekdaymarkerNonColored"][!ShowMeter "WeekdaymarkerColored"]
IfMatch2=0
IfMatchAction2=[!HideMeter "WeekdaymarkerColored"][!ShowMeter "WeekdaymarkerNonColored"]
UpdateDivier=-1

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size
