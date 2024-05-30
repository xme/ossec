#!/usr/bin/python3
#
# Submit an offensive IP address to MISP + Sighting
#
# OSSEC syntax for active-response scripts:
#
# 1. action (delete or add)
# 2. user name (or - if not set)
# 3. src ip (or - if not set)
# 4. Alert id (uniq for every alert)
# 5. Rule id
# 6. Agent name/host
# 7. Filename
#
# Required parameters: action (always "add"), src ip, rule id and agent
#

import sys
import os
import json
import ipaddress
import logging
import logging.handlers
from datetime import datetime,timezone

try:
    from pymisp import PyMISP, MISPEvent, MISPSighting, MISPTag, MISPAttribute
except:
    print("Please install pymisp")
    sys.exit(1)

try:
    import redis
except:
    print("Please install redis")
    sys.exit(1)

# === Script configuration ===

misp_url          = "https://misp.domain.tld"
misp_key          = "<redacted>"
misp_verifycert   = True
misp_info         = "OSSEC ActiveResponse"      # Event title
misp_last         = "30d"                       # Max period to search for IP address
misp_new_event    = False                       # Force the creation of a new event for every report
misp_distribution = 0                           # The distribution setting used for the newly created event, if relevant. [0-3]
misp_analysis     = 1                           # The analysis level of the newly created event, if applicable. [0-2]
misp_threat       = 3                           # The threat level ID of the newly created event, if applicable. [1-4]
misp_tags         = [ "source:OSSEC" ]          # Tags for the newly created event, if applicable
misp_publish      = True                        # Automatically puslish the event
syslog_server     = "192.168.255.8"             # If defined, enable syslog logging
redis_server      = "redis"                     # Redis server hostname/ip
redis_port        = 6379                        # Redis server port
redis_db          = 0                           # Redis server db

# === Do not change after this line ===

try:
    redis_connection = redis.Redis(host=redis_server, port=redis_port, db=redis_db)
except:
    print("Cannot connect to Redis server")
    sys.exit(1)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_rate_limited(ip):
    key = f"rate_limit:{ip}"
    # Check if the IP is already in Redis
    if redis_connection.exists(key):
        # IP is rate-limited
        return True
    else:
        # Add the IP to Redis with an expiration of 1 hour (3600 seconds)
        redis_connection.setex(key, 3600, '1')
        # IP is not rate-limited
        return False

if __name__ == "__main__":
    if len(sys.argv) < 7:
        print("Missing OSSEC Active-Response parameters")
        sys.exit(1)

    if syslog_server:
        logger = logging.getLogger('ossec2misp')
        logger.setLevel(logging.INFO)
        syslog_handler = logging.handlers.SysLogHandler(address=(syslog_server, 514))
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)

    ossec_action  = sys.argv[1] # "add" or "delete"
    ossec_srcip   = sys.argv[3] # Offending IP to block
    ossec_rule_id = sys.argv[5] # Rule that triggered
    ossec_agent   = sys.argv[6] # Agent / host
    ossec_comment = "Source: %s, Rule: %s" % (ossec_agent, ossec_rule_id)
    if syslog_server:
        logger.info("Received data: %s %s %s" % (ossec_action, ossec_srcip, ossec_comment))

    if ossec_action != "add":
        # If nothing to add, silently exit
        sys.exit(0)

    if not validate_ip(ossec_srcip):
        if syslog_server:
            logger.error("Invalid source IP address: %s" % ossec_srcip)
        sys.exit(1)

    # Check if the IP address is rate-limited (to present DoS against the MISP server)
    if is_rate_limited(ossec_srcip):
        if syslog_server:
            logger.warning("IP %s is rate-limited. Try again later." % ossec_srcip)
        sys.exit(1)

    try:
        misp = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)
    except:
        if syslog_server:
            logger.error("Can't connect to %s" % misp_url)
        sys.exit(1)

    # Get current time
    now_utc = datetime.now()
    current_time = datetime.strftime(now_utc, "%Y-%m-%dT%H:%M:%S.%f")

    # Search for the IP address
    results = misp.search(value=ossec_srcip, last=misp_last)
    if results and not misp_new_event:
        # Add sightings to all attribute occurences across the events
        for r in results:
            for a in r["Event"]["Attribute"]:
                if a["value"] == ossec_srcip:
                    # Update last_seen field
                    try:
                        attribute = MISPAttribute()
                        attribute.uuid = a["uuid"]
                        attribute.last_seen = current_time
                        misp.update_attribute(attribute)
                    except:
                        if syslog_server:
                            logger.error("Update last_seen failed on %s" % ossec_srcip)
                        sys.exit(1)

                    # Add sighting
                    # 0: sighting, 1: false-positive, 2: expiration
                    #try:
                    response = misp.add_sighting(0, a["uuid"])
                    if syslog_server:
                        logger.info("Added sighting on %s: %s" % (ossec_srcip, response["Sighting"]["id"]))
                    #except:
                    #    if syslog_server:
                    #        logger.error("Sighting failed on %s" % ossec_srcip)
                    #    sys.exit(1)
    else:
        # No event found with this IP address, add it to MISP, if "misp_new_event" set, always create a new event
        results = misp.search(eventinfo=misp_info)
        if not results or misp_new_event:
            # Create new event
            event = MISPEvent()
            event.distribution    = misp_distribution
            event.threat_level_id = misp_threat
            event.analysis        = misp_analysis
            event.info            = misp_info
            for t in misp_tags:
                tag = MISPTag()
                tag.name = t
                event.add_tag(tag)
            event = misp.add_event(event)
            event_uuid = event["Event"]["uuid"]
            if syslog_server:
                logger.info("Added new event: %s" % event_uuid)
        else:
            # Event already exists, get the UUID
            event_uuid = results[0]["Event"]["uuid"]

        # Add IP to the event
        try:
            attribute = misp.add_attribute(event_uuid,
                                           {
                                               "category": "Network activity",
                                               "type": "ip-src",
                                               "to-ids": 1,
                                               "value": ossec_srcip,
                                               "comment": ossec_comment,
                                               "first_seen": current_time,
                                               "last_seen": current_time
                                           })
            attribute_uuid = attribute["Attribute"]["uuid"]
            if syslog_server:
                logger.info("Added new attribute: %s (%s)" % (ossec_srcip, attribute_uuid))
        except:
            if syslog_server:
                 logger.error("Cannot add attribute to event %s" % event_uuid)
            attribute_uuid = None

        if attribute_uuid:
            # Add sighting to the newly created attribute
            response = misp.add_sighting(0, attribute["Attribute"]["uuid"])

        if misp_publish:
            # Publish the event
            event = misp.get_event(event_uuid)
            event = event['Event']
            misp.publish(event["id"], alert=False)
            if syslog_server:
                logger.info("Event published: %s" % event_uuid)
