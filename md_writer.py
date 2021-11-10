#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""MEETING NOTES

Big picture:

* Bodleian is writing a new client module: md_writer

* But it stills to find a way to run it in production that requires the minimum
  set of changes possible in Archivematica.

Potential strategy:

1. In production, ARCHIVEMATICA_MCPCLIENT_ARCHIVEMATICACLIENTMODULES is populated
   with a custom value indicating the path of a new modules files managed by Bodleian.

2. Similarly, Bodleian will do the seme with the workflow document, excepting
   that one is not configurable at the moment.
   Solution: we're introducing `workflow_file` in MCPServer.

3. Maintain custom workflow.json and archivematicaClientModules in a way that
   minimizes maintenance efforts.

   I.e. A deployment script that is capable to patch the vanilla Archivematica
   workflow (aka `workflow.json`) at deployment time, in order to inject the
   chain link that runs this module right after `create_mets_v2` runs.
   Similarly in archivematicaClientModules.

4. `bag_with_empty_directories._PAYLOAD_ENTRIES` - not sure yet how to do this.
   Via configuration? Using the metadata directory that is already included?
   Needs to be investigated further.

Steps to contribution the addition of `workflow_file` upstream.

1. Archivematica needs a configuration parameter to let users indicate the
   location of the JSON-encoded workflow document. The default is
   `lib/assets/workflow.json` but users may want to use a different document
   located outside the Archivematica deployment.

    We would be adding a new configuration attribut that we're proposing to name
    `ARCHIVEMATICA_MCPSERVER_WORKFLOW_FILE` that defaults to empty string but
    when defined by the user it will override the default application value.

    Based on the qa/1.x branch.

    1. This is where we add the new configuration attribute `workflow_file`.
       Module common.py is self-describing, but generally you need three changes:
       - Add new setting to CONFIG_MAPPING
       - Add default value inside CONFIG_DEFAULTS (just empty string like prometheus_bind_address)
       - At the end of the module, declare new Django setting
           WORKFLOW_FILE = config.get("workflow_file")
       https://github.com/artefactual/archivematica/blob/stable/1.12.x/src/MCPServer/lib/settings/common.py

    2. The new configuration attribute `workflow_file` needs to be documented (uses Markdown):
       https://github.com/artefactual/archivematica/blob/stable/1.12.x/src/MCPServer/install/README.md

    3. Consuming the new configuration attribute.
       Inside workflow.py, there is a `load_default_workflow` function.
       It could probably be renamed as `load_workflow`. This function should
       look up `workflow_file` and decide whether it needs to be consumed
       (when non-empty) or instaed it shoudl default to DEFAULT_WORKFLOW.
       https://github.com/artefactual/archivematica/blob/stable/1.12.x/src/MCPServer/lib/server/workflow.py

       - Import the settings module:
           from django.conf import settings as django_settings

       - Rename load_default_workflow as default_workflow.
         Remember to update references (server/test_mcp.py, server/mcp.py)

       - The implementation of default_workflow should look like this:
            def load_workflow():
                workflow_path = DEFAULT_WORKFLOW
                if django_settings.WORKFLOW_FILE != "":
                    workflow_path = django_settings.WORKFLOW_FILE
                with open(workflow_path) as workflow_file:
                    return load(workflow_file)

    4. For functional testing, you need:
       - Declare ARCHIVEMATICA_MCPSERVER_WORKFLOW_FILE inside docker-compose.yml (archivematica-mcp-server service definition).
       - Re-create container: `docker-compose up -d --force-create archivemica-mcp-server`
       - Restart MCPServer.
       E.g. ARCHIVEMATICA_MCPSERVER_WORKFLOW_FILE: "/home/sebastian/my-custom-workflow.json"

   Action items:
   - File new issue in the Archivematica repo
   - Make all changes on a new branch based on qa/1.x, only including items described above
     Not including md_writer, etc...
"""

from __future__ import print_function
import os
import json
import logging
import django
from lxml import etree
from django.db.models import Prefetch
from archivematicaFunctions import escape
import argparse
import six
from main.models import (
    Derivation,
    File,
    FPCommandOutput,
    SIP,
)

django.setup()


logger = logging.getLogger(__name__)


class FSEntries(object):
    """
    Look up required data from the database and saves them into a set.
    """

    QUERY_BATCH_SIZE = 2000

    file_queryset_prefetches = [
        "identifiers",
        "event_set",
        "event_set__agents",
        "fileid_set",
        Prefetch(
            "original_file_set",
            queryset=Derivation.objects.filter(event__isnull=False),
            to_attr="related_has_source",
        ),
        Prefetch(
            "derived_file_set",
            queryset=Derivation.objects.filter(event__isnull=False),
            to_attr="related_is_source_of",
        ),
        Prefetch(
            "fpcommandoutput_set",
            queryset=FPCommandOutput.objects.filter(
                rule__purpose__in=["characterization", "default_characterization"]
            ),
            to_attr="characterization_documents",
        ),
    ]
    file_queryset = File.objects.prefetch_related(*file_queryset_prefetches).order_by(
        "currentlocation"
    )

    def __init__(self, sip):
        self.sip = sip
        self.file_events = None
        self.md_info = {
            "dce:title": None,
            "virus_scan_info": {"virus_scan_tools": [], "failed_virus_checks": []},
            "dce:created": sip.createdtime.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dct:identifier": sip.uuid,
            "premis:size": 0,
            "amount_of_files": 0,
            "files": [],
        }

        self.load_file_data_from_db()

    def _batch_query(self, queryset):

        offset, limit = 0, self.QUERY_BATCH_SIZE
        total_count = queryset.count()

        while offset < total_count:
            batch = queryset[offset:limit]
            for item in batch:
                yield item
            offset += self.QUERY_BATCH_SIZE
            limit += self.QUERY_BATCH_SIZE

    def load_file_data_from_db(self):
        """
        loads the formatted files and appends them to the list
        """

        file_objs = self.file_queryset.filter(sip=self.sip, removedtime__isnull=True)
        for file_obj in self._batch_query(file_objs):
            self.file_events = get_file_events(file_obj)
            if not self.file_events:
                return
            try:
                # merge the map_file_data dict with the map_av_data
                mapped_file_info = merge_file_data_dicts(
                    map_file_data(file_obj, self.file_events), map_av_data(file_obj)
                )
                self.md_info["files"].append(mapped_file_info)
                self.md_info["premis:size"] = create_package_size(
                    mapped_file_info["premis:size"]
                )
                self.md_info["amount_of_files"] += 1
                failed_virus_checks = get_failed_virus_checks(self.file_events)
                if failed_virus_checks:
                    self.md_info["virus_scan_info"]["failed_virus_checks"].append(
                        failed_virus_checks
                    )
                passed_virus_checks = get_passed_virus_checks(self.file_events)
                # add info virus_scan_tools if they passed and respect
                # different tools and versions if needed.
                if (
                    passed_virus_checks
                    and passed_virus_checks
                    not in self.md_info["virus_scan_info"]["virus_scan_tools"]
                ):
                    self.md_info["virus_scan_info"]["virus_scan_tools"].append(
                        passed_virus_checks
                    )
            except KeyError:
                logger.info(
                    "File is no longer present on the filesystem: %s",
                    file_obj.currentlocation,
                )
                continue


def convert_to_premis_hash_function(hash_type):
    """
    Returns a PREMIS valid hash function name, if possible.
    """
    if hash_type.lower().startswith("sha") and "-" not in hash_type:
        hash_type = "SHA-" + hash_type.upper()[3:]
    elif hash_type.lower() == "md5":
        return "MD5"

    return hash_type


def create_package_size(file_size):
    package_size = 0
    if file_size is None:
        package_size += 0
    else:
        package_size += file_size
    return package_size


def list_file_events(file_obj_events):
    """
    get a list of the the formatted events related to the file
    """

    ret = []
    for event in file_obj_events:
        ret.append(format_file_event(event))
    return ret


def format_file_event(event):
    """
    does the mapping for the event related to the file
    """
    event_dict = {
        "premis:eventIdentifier": event.event_id,
        "event_name": event.event_type,
        "prov:softwareAgent": event.event_detail,
        "premis:outcome": event.event_outcome,
        "event_outcome_detail": event.event_outcome_detail,
    }
    return event_dict


def get_file_events(file_obj):
    """
    gets all events linked to a file_object
    """
    file_events = file_obj.event_set.all()
    return file_events


# --- This can probably be refactored in one get_event & map_event function ---


def get_file_normalization_event(file_events):
    """gets all events from the type normalization"""
    file_normalization_event = file_events.filter(event_type="normalization").first()
    if file_normalization_event:
        return file_normalization_event


def map_file_normalization_info(file_normalization_event):
    """maps the normalization event info, and therefore splits the event_detail
    to display the tool name and the tool version separately"""
    event_info = {}
    if not file_normalization_event:
        return
    try:
        event_info.update(
            {
                "premis:outcome": file_normalization_event.event_outcome_detail,
            }
        )
        if file_normalization_event.event_detail:
            event_info.update(
                {
                    "prov:softwareAgent": file_normalization_event.event_detail.split(
                        ";"
                    )[0],
                    "premis:version": file_normalization_event.event_detail.split(";")[
                        1
                    ],
                }
            )
    except IndexError:
        logger.info(
            "name and version of the file normalization tool %s could not be"
            "determined. Check if it is well formed",
            file_normalization_event.event_detail,
        )
    return event_info


def get_virusscan_events(file_events):
    """gets all events from the type virus_check"""
    virusscan_events = file_events.filter(event_type="virus check")
    if virusscan_events:
        return virusscan_events


def get_file_validation_event(file_events):
    """gets all events from the type validation"""
    file_validation_event = file_events.filter(event_type="validation").first()
    if file_validation_event:
        return file_validation_event


def map_file_validation_info(file_validation_event):
    """maps the validation event info, and therefore splits the event_detail
    to display the tool name and the tool version separately"""
    event_info = {}
    if not file_validation_event:
        return
    try:
        event_info.update(
            {
                "premis:outcome": file_validation_event.event_outcome_detail,
                "prov:softwareAgent": file_validation_event.event_detail.split(";")[0],
                "premis:version": file_validation_event.event_detail.split(";")[1],
            }
        )
    except IndexError:
        logger.info(
            "name and version of the file validation tool %s could not be"
            "determined. Check if it is well formed",
            file_validation_event.event_detail,
        )
    return event_info


def get_file_format_event(file_events):
    """gets all events from the type form identification"""
    file_format_event = file_events.filter(event_type="format identification").first()
    if file_format_event:
        return file_format_event


def map_file_format_info(file_format_event, file_validation_event):
    """maps info regarding the file format and therefore uses the
    file_format_event to get the id, tool and tool_version of the used tool, and
    takes the outcome_detail of the validation event to get the name of the file
    format, if the file has those events linked."""
    event_info = {}
    if not file_format_event:
        return
    try:
        event_info.update(
            {
                "dct:FileFormat": file_format_event.event_outcome_detail,
                "prov:softwareAgent": file_format_event.event_detail.split(";")[0],
                "premis:version": file_format_event.event_detail.split(";")[1],
            }
        )
    except IndexError:
        logger.info(
            "name and version of the file format tool %s could not be"
            "determined. Check if it is well formed",
            file_format_event.event_detail,
        )
    if file_validation_event:
        event_info.update(
            {
                "dct:FileFormat": file_validation_event.event_outcome_detail,
            }
        )
    return event_info


def get_file_name_cleanup(file_events):
    """gets all events from the type name cleanup"""
    cleanup_event = file_events.filter(event_type="name cleanup").first()
    if cleanup_event:
        return cleanup_event


def get_original_file_name(cleanup_event):
    """uses the name cleanup_event to get the first part of the event_outcome as
    original file name"""
    original_name = None
    if not cleanup_event:
        return
    try:
        original_name = cleanup_event.event_outcome_detail.split(";")[0]
    except IndexError:
        logger.info(
            "name and version of the file format tool %s could not be"
            "determined. Check if it is well formed",
            cleanup_event.event_outcome_detail,
        )
    return original_name


def get_sanitized_file_name(cleanup_event):
    """uses the name cleanup_event to get the second part of the event_outcome
    as sanitized file name"""
    sanitized_name = None
    if not cleanup_event:
        return
    try:
        sanitized_name = cleanup_event.event_outcome_detail.split(";")[1]
    except IndexError:
        logger.info(
            "name and version of the virus check tool %s could not be"
            "determined. Check if it is well formed",
            cleanup_event.event_outcome_detail,
        )
    return sanitized_name


def get_failed_virus_checks(file_events):
    """get all virus_check_events which failed and get the information of the
    event and the file_id from the files which failed the virus_check"""
    virus_check_events = get_virusscan_events(file_events)
    if not virus_check_events:
        return
    for event in virus_check_events:
        if event.event_outcome != "Pass":
            try:
                failed_file = {
                    "premis:identifier": event.file_uuid.uuid,
                    "premis:outcome": event.event_outcome,
                    "prov:softwareAgent": event.event_detail.split(";")[0],
                    "premis:version": event.event_detail.split(";")[1],
                }
            except IndexError:
                logger.info(
                    "name and version of the virus check tool %s could not be"
                    "determined. Check if it is well formed",
                    event.event_outcome_detail,
                )
                continue
            if failed_file:
                return failed_file


def get_passed_virus_checks(file_events):
    """get and return all virus_check_events which passed"""
    virus_check_events = get_virusscan_events(file_events)
    if not virus_check_events:
        return
    for event in virus_check_events:
        if event.event_outcome == "Pass":
            try:
                passed_event = {
                    "premis:outcome": event.event_outcome,
                    "prov:softwareAgent": event.event_detail.split(";")[0],
                    "premis:version": event.event_detail.split(";")[1],
                }
            except IndexError:
                logger.info(
                    "name and version of the virus check tool %s could not be"
                    "determined. Check if it is well formed",
                    event.event_outcome_detail,
                )
                continue
            if passed_event:
                return passed_event


# ----                      ----                    ----


def map_file_data(file_obj, file_events):
    """
    does the mapping of the file_object and returns the file_obj as dict
    """
    file_as_dict = {
        "premis:originalName": file_obj.currentlocation,
        "original_name": escape(file_obj.originallocation),
        # needs investigation
        "sanitized_file_name": get_sanitized_file_name(
            get_file_name_cleanup(file_events)
        ),
        "prov:generatedAtTime": file_obj.modificationtime.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "premis:fixity": {
            "checksum_type": convert_to_premis_hash_function(file_obj.checksumtype),
            "Checksum": file_obj.checksum,
        },
        "premis:identifier": file_obj.uuid,
        "premis:size": file_obj.size,
        "file_name": file_obj.label,
        # not sure if this is the file name or if we should stick with
        "dct:FileFormat": map_file_format_info(
            get_file_format_event(file_events), get_file_validation_event(file_events)
        ),
        "file_validation": map_file_validation_info(
            get_file_validation_event(file_events)
        ),
        "file_normalization": map_file_normalization_info(
            get_file_normalization_event(file_events)
        ),
        "events": list_file_events(file_events),
    }
    return file_as_dict


def merge_file_data_dicts(file_as_dict, av_data):
    merged_dict = file_as_dict.copy()
    merged_dict.update(av_data)
    return merged_dict


def get_mediainfo_info(file_obj):
    try:
        mediainfo_output = FPCommandOutput.objects.get(
            file_id=file_obj.uuid,
            rule__command__tool__description="MediaInfo",
        )
    except FPCommandOutput.DoesNotExist:
        logger.info("File object {} has no MediaInfo info.".format(file_obj.label))
        return
    mediainfo_xml = etree.fromstring(mediainfo_output.content.encode("utf8"))
    return mediainfo_xml


def query_av_data(mediainfo_xml, xml_tag, track_attr_type):
    try:
        x_query_str_to_tag = "/{https://mediaarea.net/mediainfo}" + xml_tag
        x_query_str_to_track = (
            ".//{https://mediaarea.net/mediainfo}track["
            "@type='%s']" % (track_attr_type)
        )
        final_x_query = x_query_str_to_track + x_query_str_to_tag
        element_with_audio_attr = mediainfo_xml.find(final_x_query)
        audio_element_value = element_with_audio_attr.text
        return audio_element_value
    except AttributeError:
        logger.info(xml_tag + "has no value")
        return None


def map_av_data(file_obj):
    """
    This mapping follows the conventions of a few different approached:
    https://docs.google.com/spreadsheets/d/1RVPAuiOw1pVgG2up_G-DAHgZi_C2USSSWrU8UnQ0Kts/edit#gid=0
    https://gist.github.com/finoradin/3a47fa1a0c338a8e6b9e679da489089d
    """
    mediainfo_xml = get_mediainfo_info(file_obj)
    av_data = {
        "duration": query_av_data(mediainfo_xml, "Duration", "General"),
        "bit_rate": query_av_data(mediainfo_xml, "OverallBitRate", "General"),
        "type_of_audio_codec": query_av_data(
            mediainfo_xml, "Audio_Format_List", "General"
        ),
        # unsure
        "codec_settings": query_av_data(
            mediainfo_xml, "Format_settings", "Audio"
        ),  # unsure
        "bit_depth": query_av_data(mediainfo_xml, "BitDepth", "Audio"),
        "sample_rate": query_av_data(mediainfo_xml, "SamplingRate", "Audio"),
        "number_of_channels": query_av_data(mediainfo_xml, "Channels", "Audio"),
        "channel_layout": query_av_data(
            mediainfo_xml, "ChannelLayout", "Audio"
        ),  # unsure
        "channel_sound_map_location": query_av_data(
            mediainfo_xml, "Channel_positions", "Audio"
        ),  # unsure
        "audio_stream_size": query_av_data(mediainfo_xml, "StreamSize", "Audio"),
        # Video
        "type_of_video_codec": query_av_data(
            mediainfo_xml, "Video_Format_List", "General"
        ),
        # unsure
        "video_stream": query_av_data(mediainfo_xml, "StreamKind", "Video"),
        # probably wrong
        "width": query_av_data(mediainfo_xml, "Width", "Video"),
        "height": query_av_data(mediainfo_xml, "Height", "Video"),
        "aspect_ratio": query_av_data(mediainfo_xml, "DisplayAspectRatio", "Video"),
        "frame_rate": query_av_data(mediainfo_xml, "FrameRate", "Video"),
        "lossy": query_av_data(mediainfo_xml, "Compression_Mode", "Video"),
        # probably wrong
        "video_bit_depth": query_av_data(mediainfo_xml, "BitDepth", "Video"),
        "color_subsampling": query_av_data(mediainfo_xml, "ChromaSubsampling", "Video"),
        "color_space": query_av_data(mediainfo_xml, "ColorSpace", "Video"),
        "scan_type_of_source": query_av_data(mediainfo_xml, "ScanType", "Video"),
        "audio_stream": query_av_data(mediainfo_xml, "StreamKind", "Audio"),
        "number_of_audio_channels": query_av_data(mediainfo_xml, "Channels", "Audio"),
        "audio_bit_rate": query_av_data(mediainfo_xml, "BitRate", "Audio"),
        "audio_bit_depth": query_av_data(mediainfo_xml, "BitDepth", "Audio"),
        "audio_sample_rate": query_av_data(mediainfo_xml, "SamplingRate", "Audio"),
        "video_stream_size": query_av_data(mediainfo_xml, "StreamSize", "Video"),
        # Archivematica recommended mappings
        "channel_mapping": query_av_data(
            mediainfo_xml, "Format_Settings_Endianness", "Audio"
        ),
        "channel_number": None,
        "video_duration": query_av_data(mediainfo_xml, "Duration", "Video"),
        "compression_ratio": query_av_data(mediainfo_xml, "Compression_Mode", "Video"),
        "type_of_codec": None,
    }
    return av_data


def load_file_data_from_db(sip, base_path):
    """loads the formatted sip info"""
    my_entry = FSEntries(sip)
    md_object = add_collection_name(my_entry.md_info, base_path)
    return md_object


def get_collection_name(base_path):
    base_path = os.path.join(base_path, "")
    sip_dir_name = os.path.basename(base_path.rstrip("/"))
    return sip_dir_name


def add_collection_name(md_object, base_path):
    collection_name = get_collection_name(base_path)
    if collection_name:
        md_object["dce:title"] = collection_name
    return md_object


def write_md_file(sip_uuid, filepath):
    """loads the data of the sip and writes it into a json-encoded file"""
    sip = SIP.objects.get(pk=sip_uuid)
    md_object = load_file_data_from_db(sip, filepath)
    convert_md_object = json.dumps(
        md_object, sort_keys=True, ensure_ascii=False, indent=4
    )
    filename = os.path.join(filepath, "metadata_output.json")
    with open(filename, "wb") as f:
        f.write(six.ensure_binary(convert_md_object))


def call(jobs):
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--basePath", dest="base_path")
    parser.add_argument("-S", "--sipUUID", dest="sip_uuid")
    for job in jobs:
        with job.JobContext(logger=logger):
            args = parser.parse_args(job.args[1:])
            write_md_file(args.sip_uuid, args.base_path)
