;---- Background Setting ----

[Background1]
Meter=Shape
Shape=Rectangle 10,35,185,150,3 | Fill Color 50,50,50

[Title1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=40
Text=#VarBackgroundSetting#

[Divider1]
Meter=Shape
Shape=Rectangle 12,55,181,2,0 | Fill Color 180,180,180



[ButtonDescription11]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBackgroundShadow#
X=20
Y=70

[Button11a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Circle-HideBGShadow#a.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-HideBGShadow" "0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]
[Button11b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Circle-HideBGShadow#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-HideBGShadow" "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]


[ButtonDescription12]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarColor#
X=20
Y=20r

[Button12a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnWhite.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-BGShadowColor" "255,255,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[Button12b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnBlack.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-BGShadowColor" "0,0,0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[ButtonMarker12]
Meter=Image
ImageName=#@#Images\Buttons\ColorCheckbox.png
X=-14r
Y=0r
DynamicVariables=1
[ButtonMeasure12]
Measure=String
String=#Circle-BGShadowColor#
IfMatch="0,0,0"
IfMatchAction=[!SetOption "ButtonMarker12" "X" "0r"][!UpdateMeter ButtonMarker12]


[ButtonDescription13]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineShadow#
X=20
Y=30r

[Button13a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Circle-HideRLShadow#a.png
X=138r		
Y=0r

ButtonCommand=[!WriteKeyValue Variables "Circle-HideRLShadow" "0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]
[Button13b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Circle-HideRLShadow#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-HideRLShadow" "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]


[ButtonDescription14]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarColor#
X=20
Y=20r

[Button14a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnWhite.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-RLShadowColor" "255,255,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[Button14b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnBlack.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-RLShadowColor" "0,0,0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[ButtonMarker14]
Meter=Image
ImageName=#@#Images\Buttons\ColorCheckbox.png
X=-14r
Y=0r
DynamicVariables=1
[ButtonMeasure14]
Measure=String
String=#Circle-RLShadowColor#
IfMatch="0,0,0"
IfMatchAction=[!SetOption "ButtonMarker14" "X" "0r"][!UpdateMeter ButtonMarker14]


;---- General Settings ----

[Background2]
Meter=Shape
Shape=Rectangle 205,35,185,150,3 | Fill Color 50,50,50


[Title2]
Meter=String
MeterStyle=SettingsStyle-Text
X=210
Y=40
Text=#VarOptions#


[Divider2]
Meter=Shape
Shape=Rectangle 207,55,181,2,0 | Fill Color 180,180,180


[ButtonDescription21]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarGlossyEffect#
X=215
Y=70


[Button21a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Circle-GlossyEffect#a.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-GlossyEffect" "0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[Button21b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Circle-GlossyEffect#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-GlossyEffect" "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]


[ButtonDescription22]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarFontColor#
X=215
Y=20r

[Button22a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnWhite.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-FontColor" "210,210,210,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[Button22b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnBlack.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-FontColor" "30,30,30,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[ButtonMarker22]
Meter=Image
ImageName=#@#Images\Buttons\ColorCheckbox.png
X=-14r
Y=0r
DynamicVariables=1
[ButtonMeasure22]
Measure=String
String=#Circle-FontColor#
IfMatch="30,30,30,255"
IfMatchAction=[!SetOption "ButtonMarker22" "X" "0r"][!UpdateMeter ButtonMarker22]


[ButtonDescription23]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarButtonColor#
X=215
Y=20r

[Button23a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnWhite.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-ButtonColor" "210,210,210,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[Button23b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnBlack.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-ButtonColor" "30,30,30,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[ButtonMarker23]
Meter=Image
ImageName=#@#Images\Buttons\ColorCheckbox.png
X=-14r
Y=0r
DynamicVariables=1
[ButtonMeasure23]
Measure=String
String=#Circle-ButtonColor#
IfMatch="30,30,30,255"
IfMatchAction=[!SetOption "ButtonMarker23" "X" "0r"][!UpdateMeter ButtonMarker23]


;---- Background Color ----

[Background3]
Meter=Shape
Shape=Rectangle 10,195,380,65,3 | Fill Color 50,50,50


[Title3]
Meter=String
MeterStyle=SettingsStyle-Text
Y=200
Text=#VarBackgroundcolor#


[Title3b]
Meter=String
MeterStyle=SettingsStyle-Text
Text=Pre-Sets
StringAlign=Right
X=375
Y=200


[Divider3]
Meter=Shape
Shape=Rectangle 12,215,375,2,0 | Fill Color 180,180,180


[Description3a]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBackgroundColor# R,G,B,a
X=20
Y=230


[InputBG-1]
Meter=Shape
Shape=Rectangle 159,230,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-1 "ExecuteBatch 1-2"]


[InputText-1]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=231
Text=#Circle-BGColor#
LeftMouseUpAction=[!CommandMeasure Input-1 "ExecuteBatch 1-2"]


[Input-1]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=231
H=13
FocusDismiss=0
DefaultValue=#Circle-BGColor#
Command1=[!SetVariable Circle-BGColor "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Circle-BGColor [Input-1] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Update]


[Circle-BG1]
Meter=Image
ImageName=#@#Images\Circles\BG1.png
MeterStyle=SettingsStyle-CircleBG
Y=220
X=280
MouseOverAction=[!SetOption "Title3" "Text" "#VarBackgroundcolor# | Black"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "0,0,0,255" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG2]
Meter=Image
ImageName=#@#Images\Circles\BG2.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Dark"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "30,30,30,220" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG3]
Meter=Image
ImageName=#@#Images\Circles\BG3.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Translucent Dark"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "40,40,40,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG4]
Meter=Image
ImageName=#@#Images\Circles\BG4.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Clear"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "0,0,0,1" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG5]
Meter=Image
ImageName=#@#Images\Circles\BG5.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Translucent White"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "230,230,230,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG6]
Meter=Image
ImageName=#@#Images\Circles\BG6.png
MeterStyle=SettingsStyle-CircleBG
Y=240
X=280
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Light White"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "240,240,240,180" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG7]
Meter=Image
ImageName=#@#Images\Circles\BG7.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | White"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "255,255,255,255" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG8]
Meter=Image
ImageName=#@#Images\Circles\BG8.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Red"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "180,0,0,210" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG9]
Meter=Image
ImageName=#@#Images\Circles\BG9.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Green"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "0,180,0,210" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-BG10]
Meter=Image
ImageName=#@#Images\Circles\BG10.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Blue"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-BGColor" "0,0,180,210" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]



;---- Roundline Style ----

[Background4]
Meter=Shape
Shape=Rectangle 10,270,380,385,3 | Fill Color 50,50,50


[Title4]
Meter=String
MeterStyle=SettingsStyle-Text
Y=275
Text=#VarRoundlineName#


[Divider4]
Meter=Shape
Shape=Rectangle 12,290,375,2,0 | Fill Color 180,180,180


[Circle-Bar1]
Meter=Image
ImageName=#@#Images\Circles\Bar1.png
MeterStyle=SettingsStyle-CircleRL
Y=300
X=27
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Dark Green"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "0,255,30" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "0,150,15" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "80,80,80" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.50" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar2]
Meter=Image
ImageName=#@#Images\Circles\Bar2.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Dark Red-Green"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "0,210,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "80,80,80" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.60" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar3]
Meter=Image
ImageName=#@#Images\Circles\Bar3.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Light Red-Blue"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "0,0,200" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "80,80,80" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "210,210,210,150" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.54" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar4]
Meter=Image
ImageName=#@#Images\Circles\Bar4.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Dark White-Transparent"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "240,240,240" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "40,40,40,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "80,80,80" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.24" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar5]
Meter=Image
ImageName=#@#Images\Circles\Bar5.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Gold"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "1" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "226,176,7" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "30,30,30" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar6]
Meter=Image
ImageName=#@#Images\Circles\Bar6.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Light Aqua"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "29,224,172" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "68,71,153" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "255,255,255" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "255,255,255,200" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.50" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar7]
Meter=Image
ImageName=#@#Images\Circles\Bar7.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Dark Yellow-Blue"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "200,200,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "20,20,20" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "0,0,200" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "20,20,20" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.50" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar8]
Meter=Image
ImageName=#@#Images\Circles\Bar8.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Black-Green-Black"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "0,255,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "0,40,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.52" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar9]
Meter=Image
ImageName=#@#Images\Circles\Bar9.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Black-Blue-Black"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "0,0,125" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "0,0,80" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "60,60,60" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.52" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar10]
Meter=Image
ImageName=#@#Images\Circles\Bar10.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Forever Blue"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "0,0,255" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "0,0,125" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "72,236,255" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "0,0,80" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "210,210,210,140" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.64" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar11]
Meter=Image
ImageName=#@#Images\Circles\Bar11.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Pink-Grey"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "252,38,255" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "51,59,73" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "30,30,30" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "210,210,210,180" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.52" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar12]
Meter=Image
ImageName=#@#Images\Circles\Bar12.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Blue-Pink"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "20,20,255" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "252,38,255" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "60,0,60" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.60" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar13]
Meter=Image
ImageName=#@#Images\Circles\Bar13.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Orange"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "220,126,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "255,255,255,180" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.54" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Circle-Bar14]
Meter=Image
ImageName=#@#Images\Circles\Bar14.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarRoundlineName# | Dark Red"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarRoundlineName#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Circle-RoundlineFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "60,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "0.56" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Circles]


[Button7a]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=25
Y=330
ButtonCommand=[!WriteKeyValue Variables Circle-RoundlineFillArc "0.52" "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillStyle "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]
[Button7aText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=5r
Text=#VarSingleColor#


[Button7b]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=75r
Y=-5r
ButtonCommand=[!WriteKeyValue Variables Circle-RoundlineFillArc "0.52" "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillStyle "2" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]
[Button7bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Text=#VarDualColor#


[Button7c]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=75r
Y=-5r
ButtonCommand=[!WriteKeyValue Variables Circle-RoundlineFillArc "0.52" "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillStyle "3" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]
[Button7cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Text=#VarTripleColor#


[FillStyleOptionsDisplay]
Measure=Calc
Formula=#Circle-RoundlineFillStyle#
IfCondition=FillStyleOptionsDisplay = 1
IfTrueAction=[!HideMeterGroup "FS2"][!HideMeterGroup "FS3"]
IfCondition2=FillStyleOptionsDisplay = 2
IfTrueAction2=[!ShowMeterGroup "FS2"][!HideMeterGroup "FS3"]
IfCondition3=FillStyleOptionsDisplay = 3
IfTrueAction3=[!ShowMeterGroup "FS2"][!ShowMeterGroup "FS3"]
UpdateDivider=10

[InputDescription-2]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# #VarColor# 1 (#VarUp#)
X=20
Y=380

[InputBG-2]
Meter=Shape
Shape=Rectangle 159,380,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-2 "ExecuteBatch 1-2"]
[InputText-2]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=380
Text=#Circle-RoundlineFillColor1#
LeftMouseUpAction=[!CommandMeasure Input-2 "ExecuteBatch 1-2"]
[Input-2]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=381
H=13
FocusDismiss=0
DefaultValue=#Circle-RoundlineFillColor1#
Command1=[!SetVariable Circle-RoundlineFillColor1 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Circle-RoundlineFillColor1 [Input-2] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[InputDescription-3]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# #VarColor# 2 (#VarMid#)
X=20
Y=420
Group=FS3

[InputBG-3]
Meter=Shape
Shape=Rectangle 159,420,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-3 "ExecuteBatch 1-2"]
Group=FS3

[InputText-3]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=420
Text=#Circle-RoundlineFillColor2#
LeftMouseUpAction=[!CommandMeasure Input-3 "ExecuteBatch 1-2"]
Group=FS3

[Input-3]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=421
H=13
FocusDismiss=0
DefaultValue=#Circle-RoundlineFillColor2#
Command1=[!SetVariable Circle-RoundlineFillColor2 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Circle-RoundlineFillColor2 [Input-3] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]
Group=FS3


[InputDescription-4]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# #VarColor# 3 (#VarDown#)
X=20
Y=460
Group=FS2

[InputBG-4]
Meter=Shape
Shape=Rectangle 159,460,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-4 "ExecuteBatch 1-2"]
Group=FS2

[InputText-4]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=460
Text=#Circle-RoundlineFillColor3#
LeftMouseUpAction=[!CommandMeasure Input-4 "ExecuteBatch 1-2"]
Group=FS2

[Input-4]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=461
H=13
FocusDismiss=0
DefaultValue=#Circle-RoundlineFillColor3#
Command1=[!SetVariable Circle-RoundlineFillColor3 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Circle-RoundlineFillColor3 [Input-4] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]
Group=FS2

[RoundlinePreview]
Meter=Shape
Shape=Rectangle 255,365,20,125,3 | Fill LinearGradient RLPreview#Circle-RoundlineFillStyle#
RLPreview=0 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor2# ; #Circle-RoundlineFillArc# | #Circle-RoundlineFillColor3# ; 0.0
RLPreview1=0 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor1# ; 0.0
RLPreview2=90 | #Circle-RoundlineFillColor1# ; 1.0 |  #Circle-RoundlineFillColor1# ; (#Circle-RoundlineFillArc#+0.3) | #Circle-RoundlineFillColor3# ; (#Circle-RoundlineFillArc#-0.3) | #Circle-RoundlineFillColor3# ; 0.0
RLPreview3=90 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor2# ; #Circle-RoundlineFillArc# | #Circle-RoundlineFillColor3# ; 0.0
DynamicVariables=1
UpdateDivider=5

[RoundlineArcSliderLine]
Meter=Shape
Shape=Rectangle 305,380,6,90,3 | Fill Color 0,0,0 | StrokeWidth 1 | Stroke Color 180,180,180
Group=FS2


[RoundlineArcButton]
Meter=Image
ImageName=#@#Images\General\Slider.png
SolidColor=0,0,0,1
X=298
Y=(465-#Circle-RoundlineFillArc#*100)
LeftMouseDownAction=[!ShowMeterGroup DetectArc][!Update]
LeftMouseUpAction=[!HideMeterGroup DetectArc][!Refresh]
MouseLeaveAction=[!HideMeterGroup DetectArc][!Refresh]
Group=FS2

[ArcDetectStyle]
Meter=Image
Group=DetectArc
Solidcolor=255,255,255,0
X=300
W=16
H=2
Y=2r
Hidden=1
UpdateDivider=10

[ArcDetect09]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 375  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.90"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.90" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
Y=384
[ArcDetect88]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 377  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.88"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.88" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect86]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 379  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.86"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.86" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect84]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 381  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.84"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.84" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect82]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 383  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.82"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.82" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect80]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 385  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.80"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.80" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect78]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 387  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.78"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.78" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect76]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 389  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.76"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.76" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect74]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 391  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.74"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.74" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect72]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 393  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.72"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.72" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect70]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 395  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.70"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.70" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect68]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 397  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.68"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.68" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect66]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 399  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.66"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.66" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect64]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 401  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.64"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.64" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect62]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 403  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.62"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.62" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect60]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 405  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.60"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.60" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect58]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 407  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.58"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.58" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect56]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 409  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.56"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.56" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect54]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 411  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.54"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.54" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect52]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 413  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.52"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.52" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect50]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 415  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.50"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.50" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect48]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 417  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.48"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.48" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect46]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 419  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.46"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.46" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect44]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 421  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.44"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.44" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect42]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 423  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.42"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.42" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect40]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 425  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.40"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.40" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect38]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 427  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.38"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.38" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect36]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 429  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.36"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.36" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect34]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 431  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.34"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.34" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect32]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 433  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.32"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.32" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect30]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 435  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.30"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.30" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect28]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 437  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.28"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.28" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect26]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 439  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.26"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.26" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect24]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 441  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.24"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.24" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect22]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 443  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.22"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.22" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect20]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 445  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.20"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.20" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect18]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 447  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.18"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.18" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect16]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 449  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.16"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.16" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect14]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 451  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.14"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.14" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect12]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 453  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.12"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.12" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ArcDetect10]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 455  "RoundlineArcButton"][!Redraw][!SetVariable Circle-RoundlineFillArc "0.10"][!UpdateMeter "RoundlinePreview"][!WriteKeyValue Variables Circle-RoundlineFillArc "0.10" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]

[InputDescription-5]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarDivider# #VarColor#
X=20
Y=500

[InputBG-5]
Meter=Shape
Shape=Rectangle 159,500,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-5 "ExecuteBatch 1-2"]
[InputText-5]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=500
Text=#Circle-DividerColor#
LeftMouseUpAction=[!CommandMeasure Input-5 "ExecuteBatch 1-2"]
[Input-5]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=501
H=13
FocusDismiss=0
DefaultValue=#Circle-DividerColor#
Command1=[!SetVariable Circle-DividerColor "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Circle-DividerColor [Input-5] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[InputDescription-6]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBarColor#
X=20
Y=520

[InputBG-6]
Meter=Shape
Shape=Rectangle 159,520,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-6 "ExecuteBatch 1-2"]
[InputText-6]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=520
Text=#Circle-BarColor#
LeftMouseUpAction=[!CommandMeasure Input-6 "ExecuteBatch 1-2"]
[Input-6]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=521
H=13
FocusDismiss=0
DefaultValue=#Circle-BarColor#
Command1=[!SetVariable Circle-BarColor "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Circle-BarColor [Input-6] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[RoundlinePreview3]
Meter=Shape
Shape=Rectangle 255,500,125,33,0 | Fill LinearGradient RLPreview#Circle-RoundlineFillStyle#
RLPreview=0 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor2# ; #Circle-RoundlineFillArc# | #Circle-RoundlineFillColor3# ; 0.0
RLPreview1=90 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor1# ; 0.0
RLPreview2=0 | #Circle-RoundlineFillColor1# ; 1.0 |  #Circle-RoundlineFillColor1# ; (#Circle-RoundlineFillArc#+0.3) | #Circle-RoundlineFillColor3# ; (#Circle-RoundlineFillArc#-0.3) | #Circle-RoundlineFillColor3# ; 0.0
RLPreview3=0 | #Circle-RoundlineFillColor1# ; 1.0 | #Circle-RoundlineFillColor2# ; #Circle-RoundlineFillArc# | #Circle-RoundlineFillColor3# ; 0.0
DynamicVariables=1

[RoundlinePreview2]
Meter=Shape
Shape=Rectangle 255,500,125,33,3 | Fill Color #Circle-BarColor# | StrokeWidth 3 | Stroke Color #Circle-DividerColor#
Shape2=Rectangle 285,503,2,27,3 | Fill Color #Circle-DividerColor# | StrokeWidth 0
Shape3=Rectangle 315,503,2,27,3 | Fill Color #Circle-DividerColor# | StrokeWidth 0
Shape4=Rectangle 345,503,2,27,3 | Fill Color #Circle-DividerColor# | StrokeWidth 0
DynamicVariables=1


;---- Custom Presets ----

[ButtonCP1]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=350
Y=380
ToolTipTitle=Custom Preset
ToolTipText=LeftMouse: Load #1 #CRLF#RightMouse: Save to #1
ButtonCommand=[!WriteKeyValue Variables "Circle-GlossyEffect" "#Circle-GlossyEffect-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-FontColor" "#Circle-FontColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillStyle" "#Circle-RoundlineFillStyle-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "#Circle-RoundlineFillColor1-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "#Circle-RoundlineFillColor2-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "#Circle-RoundlineFillColor3-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "#Circle-RoundlineFillArc-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "#Circle-BarColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "#Circle-DividerColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGColor" "#Circle-BGColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGShadowColor" "#Circle-BGShadowColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideRLShadow" "#Circle-HideRLShadow-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideBGShadow" "#Circle-HideBGShadow-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-ButtonColor" "#Circle-ButtonColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RLShadowColor" "#Circle-RLShadowColor-CP1#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
RightMouseUpAction=[!WriteKeyValue Variables "Circle-GlossyEffect-CP1" "#Circle-GlossyEffect#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-FontColor-CP1" "#Circle-FontColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillStyle-CP1" "#Circle-RoundlineFillStyle#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1-CP1" "#Circle-RoundlineFillColor1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2-CP1" "#Circle-RoundlineFillColor2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3-CP1" "#Circle-RoundlineFillColor3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc-CP1" "#Circle-RoundlineFillArc#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor-CP1" "#Circle-BarColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor-CP1" "#Circle-DividerColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGColor-CP1" "#Circle-BGColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGShadowColor-CP1" "#Circle-BGShadowColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideRLShadow-CP1" "#Circle-HideRLShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideBGShadow-CP1" "#Circle-HideBGShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-ButtonColor-CP1" "#Circle-ButtonColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RLShadowColor-CP1" "#Circle-RLShadowColor#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ButtonTextCP1]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=5r
Text=#1

[ButtonCP2]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=-12r
Y=30r
ToolTipTitle=Custom Preset
ToolTipText=LeftMouse: Load #2 #CRLF#RightMouse: Save to #2
ButtonCommand=[!WriteKeyValue Variables "Circle-GlossyEffect" "#Circle-GlossyEffect-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-FontColor" "#Circle-FontColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillStyle" "#Circle-RoundlineFillStyle-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "#Circle-RoundlineFillColor1-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "#Circle-RoundlineFillColor2-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "#Circle-RoundlineFillColor3-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "#Circle-RoundlineFillArc-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "#Circle-BarColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "#Circle-DividerColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGColor" "#Circle-BGColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGShadowColor" "#Circle-BGShadowColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideRLShadow" "#Circle-HideRLShadow-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideBGShadow" "#Circle-HideBGShadow-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-ButtonColor" "#Circle-ButtonColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RLShadowColor" "#Circle-RLShadowColor-CP2#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
RightMouseUpAction=[!WriteKeyValue Variables "Circle-GlossyEffect-CP2" "#Circle-GlossyEffect#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-FontColor-CP2" "#Circle-FontColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillStyle-CP2" "#Circle-RoundlineFillStyle#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1-CP2" "#Circle-RoundlineFillColor1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2-CP2" "#Circle-RoundlineFillColor2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3-CP2" "#Circle-RoundlineFillColor3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc-CP2" "#Circle-RoundlineFillArc#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor-CP2" "#Circle-BarColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor-CP2" "#Circle-DividerColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGColor-CP2" "#Circle-BGColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGShadowColor-CP2" "#Circle-BGShadowColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideRLShadow-CP2" "#Circle-HideRLShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideBGShadow-CP2" "#Circle-HideBGShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-ButtonColor-CP2" "#Circle-ButtonColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RLShadowColor-CP2" "#Circle-RLShadowColor#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
[ButtonTextCP2]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=5r
Text=#2

[ButtonCP3]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=-12r
Y=30r
ToolTipTitle=Custom Preset
ToolTipText=LeftMouse: Load #3 #CRLF#RightMouse: Save to #3
ButtonCommand=[!WriteKeyValue Variables "Circle-GlossyEffect" "#Circle-GlossyEffect-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-FontColor" "#Circle-FontColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillStyle" "#Circle-RoundlineFillStyle-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1" "#Circle-RoundlineFillColor1-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2" "#Circle-RoundlineFillColor2-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3" "#Circle-RoundlineFillColor3-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc" "#Circle-RoundlineFillArc-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor" "#Circle-BarColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor" "#Circle-DividerColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGColor" "#Circle-BGColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGShadowColor" "#Circle-BGShadowColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideRLShadow" "#Circle-HideRLShadow-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideBGShadow" "#Circle-HideBGShadow-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-ButtonColor" "#Circle-ButtonColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RLShadowColor" "#Circle-RLShadowColor-CP3#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles]
RightMouseUpAction=[!WriteKeyValue Variables "Circle-GlossyEffect-CP3" "#Circle-GlossyEffect#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-FontColor-CP3" "#Circle-FontColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillStyle-CP3" "#Circle-RoundlineFillStyle#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor1-CP3" "#Circle-RoundlineFillColor1#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor2-CP3" "#Circle-RoundlineFillColor2#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillColor3-CP3" "#Circle-RoundlineFillColor3#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RoundlineFillArc-CP3" "#Circle-RoundlineFillArc#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BarColor-CP3" "#Circle-BarColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-DividerColor-CP3" "#Circle-DividerColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGColor-CP3" "#Circle-BGColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-BGShadowColor-CP3" "#Circle-BGShadowColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideRLShadow-CP3" "#Circle-HideRLShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-HideBGShadow-CP3" "#Circle-HideBGShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-ButtonColor-CP3" "#Circle-ButtonColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-RLShadowColor-CP3" "#Circle-RLShadowColor#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][ButtonTextCP3]
[ButtonTextCP3]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=5r
Text=#3


;---- Settings Import ----

[BackgroundImport]
Meter=Shape
Shape=Rectangle 10,665,380,70,3 | Fill Color 50,50,50

[TitleImport]
Meter=String
MeterStyle=SettingsStyle-Text
Y=670
Text=Import

[DividerImport]
Meter=Shape
Shape=Rectangle 12,685,375,2,0 | Fill Color 180,180,180

[ButtonImport]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25
Y=695
ButtonCommand=[!WriteKeyValue Variables Circle-FontColor #Panel-FontColor# "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillStyle #Panel-BarFillStyle# "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillColor1 #Panel-BarFillColor1# "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillColor2 #Panel-BarFillColor2# "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillColor3 #Panel-BarFillColor3# "#@#Variables.inc"][!WriteKeyValue Variables Circle-RoundlineFillArc #Panel-BarFillArc# "#@#Variables.inc"][!WriteKeyValue Variables Circle-BarColor #Panel-BarColor# "#@#Variables.inc"][!WriteKeyValue Variables Circle-DividerColor #Panel-StrokeColor# "#@#Variables.inc"][!WriteKeyValue Variables Circle-BGColor #Panel-BGColor# "#@#Variables.inc"][!WriteKeyValue Variables Circle-BGShadowColor #Panel-BGShadowColor# "#@#Variables.inc"][!WriteKeyValue Variables Circle-ButtonColor #Panel-ButtonColor# "#@#Variables.inc"][!WriteKeyValue Variables Circle-HideBGShadow #Panel-HideShadow# "#@#Variables.inc"][!RefreshGroup SYSMonitor-Circles][!Refresh]

[ButtonImportText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=175r
Text=#VarImportColorSettings2#
