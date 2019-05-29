# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

import configparser
import re
import subprocess

import lib.helpers.directory_helper as directory_helper

from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm


class PDFExportError(Exception):
    """ Custom Exception for the PDFWriter class
    """

    def __init__(self, msg):
        Exception.__init__(self, msg)


class PDFWriter:
    """ Outputs a PDF file containing all the information gathered from a phase of the TFG ESEI 2018-19 tool.

    This class uses the pdf.ini config file for easier and flexible output depending on the information to export.
    This this file must be filled in order to let the PDFWriter instance know what to write in the document.
    The exported PDF hast multi-language support, but for now the PSCAD application only exports in spanish.

    Class static attributes are defined to make that PDFWriter class easier to use and scalable:

        LANGS: list. Contains all the valid languages. For each 'lang' on this list, the pdf.ini file
        must have a <key>.lang = <value> representing the original <value> translated.
        STYLES: List of fonts, font sizes and alignment gathered in reportlab objects to write the PDF document.

    PDFWriter __init__ arguments are defined below:

        :param lang: Output language. Only 'esp' or 'en' are valid.
        :param output_directory: Directory where to output the PDF file
        :type lang: str
        :type output_directory: str

    Apart from the __init__ function parameters, this class has more attributes.
    Attributes:
        __config: dict containing all the information from the parsed 'pdf.ini' file
        __output: list where to store the dynamic information to export.
    """

    LANGS = ['esp', 'en']
    STYLES = getSampleStyleSheet()

    def __init__(self, lang='en', output_directory='./'):

        if lang not in PDFWriter.LANGS:
            raise PDFExportError('{} language is not supported'.format(lang))

        self.__lang = lang
        self.__output_directory = output_directory
        # Load config from pdf.ini
        self.__config = configparser.ConfigParser()
        self.__config.read('config/pdf.ini')

        # Output to write
        self.__output = []

        # Load paragraph styles
        PDFWriter.add_default_styles()

    @staticmethod
    def add_default_styles():
        """ Loads the styles needed to export the PDF document to the class static variable STYLES.
        """
        # File title font
        PDFWriter.STYLES.add(ParagraphStyle(name='cover_header', alignment=TA_CENTER, fontsize=30,
                                            fontName='Helvetica'))
        # Cover contact font
        PDFWriter.STYLES.add(ParagraphStyle(name='cover_right', alignment=TA_RIGHT))
        # Section title
        PDFWriter.STYLES.add(ParagraphStyle(name='titled', alignment=TA_CENTER, fontsize=15))
        # Section subttitle
        PDFWriter.STYLES.add(ParagraphStyle(name='subtitle', fontsize=10))
        # Section body
        PDFWriter.STYLES.add(ParagraphStyle(name='body', fontsize=8))
        # Justified section body
        PDFWriter.STYLES.add(ParagraphStyle(name='body_justify', alignment=TA_JUSTIFY, fontsize=8))

    def __build_file_name(self):
        """ Creates the file name from the file output directory, the file title and the current date.

            :returns: File name from the PDF document.
            :rtype: str

        warning::
            PDF title must not have dots '.', if so, they will be deleated with all the rest of the text.
        """
        index = 'title.' + self.__lang
        title = self.__config['COVER'][index]
        # Remove lateral black spaces, capital letters and replace rest of black spaces with underscores
        title = title.strip().lower().replace(' ', '_')
        # Add date to PDF file name
        title = title + '{}'.format(datetime.now().date())

        # If title has dots, remove then. Need the dot for the extension
        if '.' in title:
            title = re.sub('\..*', '', title)

        # Return the output directory (without last '/')/file_name.pdf
        return directory_helper.process_directory(self.__output_directory) + '/' + title + '.pdf'

    def append_info(self, single_data, table_data, headers_list, col_widths=None):
        """Appends data to the PDF document structure.

        All the PDFs created will have a cover, an introduction text and the information gathered. This information
        is divided in sections, each section per target. This methods has to be called for eery section.
        Each section contains static information, which is, data that will appear once per section, and dynamic
        information, displayed as tables. The single data parameter is a dictionary, which defines the static
        information, formed by string keys that determine the data "name", and values, that are the data itself.
        The table_data attributes is a list of lists, each list containing the information of a table row.
        The headers_list is a list of all the headers to display in the table, and it has to be the same size as
        the number of columns displayed. col_widths, None by default, is an optional parameter that can be a list
        containing each column width, and it has the be the same size as the number of columns displayed.

            :param single_data: Static data
            :param table_data: Dynamic data
            :param headers_list: Column headers
            :param col_widths: Column widths
            :type single_data: dict
            :type table_data: list
            :type headers_list: list
            :type col_widths: None, list
        """

        # For each entry of static data, print the key with front size 13 and bold text
        # Append ': ' and then write the value.
        for text, value in single_data.items():
            self.__output.append(Paragraph('<b><font size=13>' + text + ': ' + value + '</font></b>',
                                           PDFWriter.STYLES['Normal']))
            # Space the data
            self.__output.append(Spacer(1,5))

        # Reportlab cell formatting
        all_cells = [(0, 0), (-1, -1)]
        header = [(0, 0), (-1, 0)]
        # Empty list for storing columns and table styles
        columns = []
        table_style = []

        # For each header, create a column
        for col_index in range(len(headers_list)):
            columns.append([(col_index, 0), (col_index, -1)])

        # For each column, add a style to them
        for column in columns:
            table_style.append(('ALIGN', column[0], column[1], 'LEFT'))

        # Add generic styles
        table_style.append(('VALIGN', all_cells[0], all_cells[1], 'TOP'))
        table_style.append(('LINEBELOW', header[0], header[1], 0.25, colors.black))
        table_style.append(('INNERGRID', all_cells[0], all_cells[1], 0.25, colors.black))
        table_style.append(('BOX', all_cells[0], all_cells[1], 0.25, colors.black))

        # If no width for columns specified , use 2.5cm for each column
        if col_widths is None:
            col_widths = []
            for _ in columns:
                col_widths.append(2.5 * cm)
        else:
            col_widths = [x*cm for x in col_widths]

        # Assign the data to a particular cell
        for index, row in enumerate(table_data):
            for col, val in enumerate(row):
                table_data[index][col] = Paragraph(val, ParagraphStyle('normal'))
        # Insert the headers at the beginning
        table_data.insert(0, [Paragraph(x, ParagraphStyle('Normal')) for x in headers_list])

        # Generate the table with a specified width and set styles
        table = Table(table_data, colWidths=col_widths)
        table.setStyle(TableStyle(table_style))
        # Space from static data
        self.__output.append(Spacer(1, 15))
        self.__output.append(table)
        # Space after table
        self.__output.append(Spacer(1, 30))

    def write_document(self):
        """ Writes the entire PDF document, from the php.ini and the information previously loaded.
        """

        file_name = self.__build_file_name()

        # If file exists, delete it
        try:
            open(file_name, 'r')
            subprocess.call(['rm', file_name])
        except EnvironmentError:
            pass

        # Create the document
        doc = SimpleDocTemplate(file_name,
                                pagesize=letter, rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        # Logo path
        logo = './assets/logo.jpg'
        cover = []

        # Create Image object and size it
        try:
            logo_img = Image(logo, 4*inch, 5*inch)
        except:
            raise PDFExportError('Cannot create PDF document without the logo image. Must be under assets with the name'
                                 'of logo.fpg on project root directory: ./assets/logo.jpg')

        # Write Title
        # Get title index from config
        index = 'title.' + self.__lang
        current_text = '<font size=30>{}</font>'.format(self.__config['COVER'][index])
        # Add title to output with 'cover_header' style
        cover.append(Paragraph(current_text, PDFWriter.STYLES['cover_header']))
        # Space vertically 100 units
        cover.append(Spacer(1, 100))
        # Append the logo
        cover.append(logo_img)
        # Space vertically 70 units
        cover.append(Spacer(1, 70))

        # Write date with normal style and space 12 units
        cover.append(Paragraph('<strong>{}</strong>'.format(datetime.now().date()), PDFWriter.STYLES['Normal']))
        cover.append(Spacer(1, 12))

        # Write sender information
        # Get author information for a given language
        index = 'author.' + self.__lang
        cover.append(Paragraph(self.__config['COVER'][index], PDFWriter.STYLES['Normal']))
        # Get email, which is the same line, language independent
        cover.append(Paragraph(self.__config['COVER']['author_email'], PDFWriter.STYLES['Normal']))
        # Get author telephone number for a given language
        index = 'author_telephone.' + self.__lang
        cover.append(Paragraph(self.__config['COVER'][index], PDFWriter.STYLES['Normal']))
        cover.append(Spacer(1, 12))

        # Write receiver information
        # Get destination business for a given language
        index = 'business.' + self.__lang
        cover.append(Paragraph(self.__config['COVER'][index], PDFWriter.STYLES['cover_right']))
        # Get business responsible for a given langugage
        index = 'receiver.' + self.__lang
        cover.append(Paragraph(self.__config['COVER'][index], PDFWriter.STYLES['cover_right']))
        # Get email, which is the same line, language independent
        cover.append(Paragraph(self.__config['COVER']['receiver_email'], PDFWriter.STYLES['cover_right']))
        # Stop writing in the first page
        cover.append(Spacer(1, 24))

        # Write the presentation and introduction text spacing them.
        index = 'common.' + self.__lang
        common_paragraph = Paragraph(self.__config['PRESENTATION'][index], PDFWriter.STYLES['body_justify'])
        cover.append(common_paragraph)
        cover.append(Spacer(1,14))
        index = 'intro.' + self.__lang
        intro_paragraph = Paragraph(self.__config['INTRO'][index], PDFWriter.STYLES['body_justify'])
        cover.append(intro_paragraph)
        cover.append(Spacer(1, 100))

        # Extend the list with the self.__output elements
        cover.extend(self.__output)

        # Build the doc
        doc.build(cover)

