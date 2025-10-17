#!/usr/bin/env python
# Declare the formatting style we will later use in various Excel spreadsheets when we export data.
# new model of style dictionary to replace legacy object methodology. Will remove objects as they are replaced with the new dictionary model.

styles = {
    'label': {
        'bold': 1,
        'align': 'center',
        'valign': 'vcenter'},
    'rowHeader': {
        'bold': 1,
        'align': 'center',
        'bottom': 2},
    'centeredText': {
        'bold': 0,
        'align': 'left',
        'valign': 'vcenter'},
    'normalText': {
        'bold': 0,
        'align': 'left',
        'valign': 'vcenter',
        'border': 1,
        'bg_color': '#FFFFFF'},
    'greyBackground': {
        'bold': 0,
        'align': 'left',
        'valign': 'vcenter',
        'border': 1,
        'bg_color': '#D3D3D3'},
    'wrappedText': {
        'bold': 0,
        'align': 'left',
        'valign': 'vcenter',
        'border': 1,
        'text_wrap': True,
        'bg_color': '#FFFFFF'},
    'warnText': {
        'bold': 1,
        'align': 'left',
        'text_wrap': True,
        'border': 1,
        'bg_color':	'#A6A6A6',
        'font_color': '#FF0000'},
    'alertText': {
        'bold': 1,
        'align': 'left',
        'border': 1,
        'bg_color':	'#FF0000',
        'font_color': '#FFFF00'},
    'blackBox': {
        'bg_color': '#000000'},
    'vAlignCenter': {
        'valign': 'vcenter'}
    }

"""
# Legacy style objects below. Will be removed as phased out to dictionary approach above.

# DO NOT USE OBJECTS! WILL BE DEPRECATED.

Label = {
    'bold': 1,
    'align': 'center',
    'valign': 'vcenter'}

RowHeader = {
    'bold': 1,
    'align': 'center',
    'bottom': 2}

normalText = {
    'bold': 0,
    'align': 'left',
    'valign': 'center',
    'border': 1,
    'bg_color': '#FFFFFF'}

wrappedText = {
    'bold': 0,
    'align': 'left',
    'valign': 'center',
    'border': 1,
    'text_wrap': True,
    'bg_color': '#FFFFFF'}

warnText = {
    'bold': 1,
    'align': 'left',
    'border': 1,
    'bg_color':	'#A6A6A6',
    'font_color': '#FF0000'
}

alertText = {
    'bold': 1,
    'align': 'left',
    'border': 1,
    'bg_color':	'#FF0000',
    'font_color': '#FFFF00'
}


BlackBox = {'bg_color': '#000000'}

SeparatorRow = {
    'bottom': 0,
    'top': 0}

ColBorders = {
    'left': 1,
    'right': 1
}

vAlignCenter = {
    'valign': 'center'
}
"""