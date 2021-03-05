[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc


;---- Measures Volume ----

[VolumeWin]
Measure			=Plugin
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinPercent]
Measure			=Calc
Formula			=VolumeWin
UpdateDivider	=1
IfCondition		=(VolumeWinPercent = -1) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfFalseAction	=[!HideMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfCondition2	=(VolumeWinPercent > 0) && (#WRActive# = 1)
IfTrueAction2	=[!HideMeter "ButtonMute"][!ShowMeter "ButtonVol"]
DynamicVariables=1

[FunctionSwitch]
Measure			=Calc
Formula			=#WRHideVolume#+#WRShowColoredBtnFrame#
IfCondition		=(#WRHideVolume# = 0) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "Volume"][!HideMeterGroup AudioBar]
IfFalseAction	=[!HideMeter "Volume"]
IfCondition2	=(#WRShowColoredBtnFrame# = 1)
IfTrueAction2	=[!SetVariable CurrentBarColor #Panel-BarFillColor3#]
DynamicVariables=1
Updatedivider	=1


;---- Measures Audiolevel ----

[WinAudioLevel]
	Measure=Plugin
	Plugin=AudioLevel
	Port=Output
	FFTSize=1024
	FFTAttack=15
	FFTDecay=200
	Bands=5
	UpdateDivier=1
[Band0]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=0
[Band1]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=1
[Band2]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=2
[Band3]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=3
[Band4]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=4
	

;---- Default Cover & Station ----

[SpeakerLogo]
	Meter=Image
	ImageName=#@#Images\General\Speaker.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.047)
	W=(#PHeight#*0.29)
	H=(#PHeight#*0.29)
	Hidden=#WRActive#
	Group=RadioOff
	DynamicVariables=1
	Updatedivider=-1

[Title]
	Meter=String
	MeterStyle=PText | PTitle
	StringAlign=Left
	X=(#PHeight#*0.46)
	Y=(#PHeight#*0.12)
	Text=Webradio
	Group=RadioOff
	Hidden=#WRActive#
	DynamicVariables=1
	Updatedivider=-1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!ShowMeterGroup Stations]
MouseScrollDownAction=[!CommandMeasure "VolumeWin" "ChangeVolume -3"]
MouseScrollUpAction=[!CommandMeasure "VolumeWin" "ChangeVolume +3"]


;---- Active Cover & Station ----

[Cover]
	Meter=Image
	ImageName=#@#Images\Stations\#WRASImage#
	AntiAlias=1
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.07)
	W=(#PHeight#*0.25)
	H=(#PHeight#*0.25)
	Hidden=#WRInactive#
	Group=Radio
	LeftMouseUpAction=[#WRASTracklist#]
	DynamicVariables=1
	UpdateDivider=10

[Volume]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=Center
	MeasureName=VolumeWinPercent
	X=(#PHeight#*0.95)
	Y=(#PHeight#*0.16)
	Group=Radio
	Hidden=#WRInactive#
	Text=Vol#CRLF#%1
	UpdateDivider=3

[SationText]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Left
	X=(#PHeight#*0.37)
	Y=(#PHeight#*0.05)
	Hidden=#WRInactive#
	Group=Radio
	Text=#WRASTitle#
	UpdateDivider=10


;---- Buttons ----

[ButtonFrame]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.37),(#PHeight#*0.2),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	Shape2=Rectangle (#PHeight#*0.50),(#PHeight#*0.2),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	Shape3=Rectangle (#PHeight#*0.63),(#PHeight#*0.2),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	Shape4=Rectangle (#PHeight#*0.76),(#PHeight#*0.2),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	ButtonFrameColor01=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor02=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor03=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor11=90 | #Panel-BarFillColor1# ; 0.0 | #Panel-BarFillColor1# ; 1.0
	ButtonFrameColor12=90 | #Panel-BarFillColor3# ; 0.0 |  #Panel-BarFillColor1# ; 1.0
	ButtonFrameColor13=90 | #Panel-BarFillColor3# ; 0.0 | #Panel-BarFillColor2# ; 0.5 | #Panel-BarFillColor1# ; 1.0
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=10

[ButtonVol]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVol.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.39)	
	Y=(#PHeight#*0.22)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonVol ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonVol ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonMute]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVolMute.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.39)	
	Y=(#PHeight#*0.22)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonMute ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonMute ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonStop]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStop.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.52)	
	Y=(#PHeight#*0.22)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStop ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStop ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "1" "#@#Variables.inc"]["#@#Tools\omnimoapp.exe" Radio Kill][!HideMeterGroup Radio][!ShowMeterGroup RadioOff][!Redraw]
	UpdateDivider=1

[ButtonPlay]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPlay.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.65)		
	Y=(#PHeight#*0.22)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=1
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPlay ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPlay ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#WRASStream#"][!HideMeter ButtonPlay][!ShowMeter ButtonPause]
	UpdateDivider=1

[ButtonPause]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPause.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.65)		
	Y=(#PHeight#*0.22)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPause ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPause ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" Off][!HideMeter ButtonPause][!ShowMeter ButtonPlay]
	UpdateDivider=1

[ButtonStations]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStations.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.78)		
	Y=(#PHeight#*0.22)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStations ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStations ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!ShowMeterGroup Stations]
	UpdateDivider=1


;---- Audiolevelmeter ----

[StyleAudioBar]
	Flip=0
	BarColor=#CurrentBarColor#
	SolidColor=#Panel-BGShadowColor#,20
	BarOrientation=Vertical
	Y=(#PHeight#*0.2)
	W=(#PHeight#*0.02)
	H=(#PHeight#*0.1)
	Group=Radio | AudioBar
	AntiAlias=1
	DynamicVariables=1
	Hidden=#WRInactive#
	UpdateDivider=1
[MeterBand0]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band0
	X=(#PHeight#*0.89)
[MeterBand1]
	Meter=Bar
	MeasureName=Band1
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.92)
[MeterBand2]
	Meter=Bar
	MeasureName=Band2
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.95)
[MeterBand3]
	Meter=Bar
	MeasureName=Band3
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.98)
[MeterBand4]
	Meter=Bar
	MeasureName=Band4
	MeterStyle=StyleAudiobar
	X=(#PHeight#*1.01)
	

;---- Skin Functions ----

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size


;---- Station list ----

[Stationlistbackground]
Meter=Shape
Shape=Rectangle (#PHeight#*0.040),(#PHeight#*0.040),(#PHeight#),(#PHeight#),(#PHeight#*0.032) | Fill Color 0,0,0,200 | StrokeWidth (#PHeight#*0.004) | Stroke Color 255,255,255
Group=Stations
DynamicVariables=1
AntiAlias=1
Hidden=1
MouseLeaveAction=[!HideMeterGroup Stations]
UpdateDivider=-1

[Station1]
Meter=String
MeterStyle=PStations
Y=(#PHeight#*0.03)	
Text=#StationTitle1#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "1"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle1#"][!WriteKeyValue Variables "WRASImage" "#StationImage1#"][!WriteKeyValue Variables "WRASStream" "#StationURL1#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL1#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL1#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption Station1 FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption Station1 FontColor 210,210,210,255]

[Station2]
Meter=String
MeterStyle=PStations
Text=#StationTitle2#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "2"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle2#"][!WriteKeyValue Variables "WRASImage" "#StationImage2#"][!WriteKeyValue Variables "WRASStream" "#StationURL2#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL2#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL2#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station3]
Meter=String
MeterStyle=PStations
Text=#StationTitle3#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "3"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle3#"][!WriteKeyValue Variables "WRASImage" "#StationImage3#"][!WriteKeyValue Variables "WRASStream" "#StationURL3#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL3#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL3#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station4]
Meter=String
MeterStyle=PStations
Text=#StationTitle4#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "4"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle4#"][!WriteKeyValue Variables "WRASImage" "#StationImage4#"][!WriteKeyValue Variables "WRASStream" "#StationURL4#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL4#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL4#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station5]
Meter=String
MeterStyle=PStations
Text=#StationTitle5#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "5"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle5#"][!WriteKeyValue Variables "WRASImage" "#StationImage5#"][!WriteKeyValue Variables "WRASStream" "#StationURL5#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL5#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL5#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station6]
Meter=String
MeterStyle=PStations
Text=#StationTitle6#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "6"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle6#"][!WriteKeyValue Variables "WRASImage" "#StationImage6#"][!WriteKeyValue Variables "WRASStream" "#StationURL6#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL6#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL6#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station7]
Meter=String
MeterStyle=PStations
Text=#StationTitle7#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "7"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle7#"][!WriteKeyValue Variables "WRASImage" "#StationImage7#"][!WriteKeyValue Variables "WRASStream" "#StationURL7#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL7#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL7#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station8]
Meter=String
MeterStyle=PStations
Text=#StationTitle8#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "8"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle8#"][!WriteKeyValue Variables "WRASImage" "#StationImage8#"][!WriteKeyValue Variables "WRASStream" "#StationURL8#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL8#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL8#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]
