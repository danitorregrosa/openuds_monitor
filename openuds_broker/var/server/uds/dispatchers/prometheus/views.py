# -*- coding: utf-8 -*-

#       openuds dispatcher to generate prometheus metrics
#
# Copyright (C) 2020-2021 Daniel Torregrosa
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import logging
import datetime
import time

from django.http import HttpResponseNotAllowed, HttpResponse, HttpRequest, HttpResponseForbidden
from uds.core.util import net
from uds.models import Authenticator
from uds.models import ServicePool

logger = logging.getLogger(__name__)

uds_v4, uds_v3 = True, False
if hasattr(ServicePool, "isInMaintenance"):
    uds_v4, uds_v3 = False, True

# to allow this endpoint only for some ips put here separated by commas
# e.g:
# ALLOWED_IPS = '192.168.1.5, 192.168.1.45, 192.168.1.72'
# if empty, allows any client
ALLOWED_IPS = ''


def clean(label):
    '''
    # https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels
    #    metrics: [a-zA-Z_:][a-zA-Z0-9_:]*
    #    labels: [a-zA-Z_][a-zA-Z0-9_]*
    '''
    ALLOWED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'

    ret = ''.join([char if char in ALLOWED else '_' for char in label])

    while '__' in ret:
        ret = ret.replace('__', '_')

    # first letter in [a-zA-Z] (also delete allowed '_')
    while len(ret) and ret[0] in '0123456789_':
        ret = ret[1:]

    if len(ret) == 0:
        # we should not be here
        ret = 'A'

    return ret


def map_name(id_, label):
    '''
    very dirty hack to allow pool/auth name modifications in openuds maintaining
    old metric name

    Problem: if we modify pool/authentication name in openuds
      - prometheus data is saved associate with pool/auth name
      - at the end with have two separate metrics, one for older name and one
        for newer one
      - prometheus accepts 'label_replace' but needs to modify queries
        https://prometheus.io/docs/prometheus/latest/querying/functions/#label_replace

    ToDo: can we make prometheus name/label modifications in *old* data ?
    '''

    ID_NAME_MAPS = {
      # auths:
      # eg:
      # '75379983-cdfe-5228-9f67-1af5962575d8': 'internal_mapped',
      # service pools:

      }

    ret = label

    if ID_NAME_MAPS.get(id_):
        ret = ID_NAME_MAPS.get(id_)

    return clean(ret)


def prometheus_metrics(request: HttpRequest) -> HttpResponse:
    '''
    response with openuds metrics for:
    A. authenticators
    B. providers
    C. provider services
    D. service pools
    '''

    # manual ip check instead of auth.trustedSourceRequired decorator
    if len(ALLOWED_IPS) and not net.ipInNetwork(request.ip, ALLOWED_IPS):
        return HttpResponseForbidden()
    if request.method == 'POST':
        return HttpResponseNotAllowed(['GET'])

    start_time = time.time()

    response = ''

    # A. authenticators
    # names prefix: openuds_auth_
    for auth in Authenticator.objects.all():
        auth_name = map_name(auth.uuid, auth.name)
        response += '# HELP openuds_auth_users_total Total number of users.\n'
        response += '# TYPE openuds_auth_users_total counter\n'
        response += ('openuds_auth_users_total{auth="%s"} %d\n'
                     % (auth_name, auth.users.count()))
        response += '# HELP openuds_auth_groups_total Total number of groups.\n'
        response += '# TYPE openuds_auth_groups_total gauge\n'
        response += ('openuds_auth_groups_total{auth="%s"} %d\n'
                     % (auth_name, auth.groups.count()))

    # ToDo
    # B. providers
    # names prefix: openuds_provider_

    # ToDo
    # C. provider services
    # names prefix: openuds_providerservice_

    # D. service pools
    # names prefix: openuds_pool_
    sps = ServicePool.objects.all()
    response += '# HELP openuds_pool_total Total number of pools.\n'
    response += '# TYPE openuds_pool_total gauge\n'
    response += 'openuds_pool_total %d\n' % (len(sps))

    for sp in sps:
        sp_name = map_name(sp.uuid, sp.name)
        response += '# HELP openuds_pool_pub_revision Pool publication revision.\n'
        response += '# TYPE openuds_pool_pub_revision counter\n'
        response += ('openuds_pool_pub_revision{pool="%s"} %d\n'
                     % (sp_name, int(sp.current_pub_revision)))

        # access_allowed / maintenance / restrained
        response += '# HELP openuds_pool_access_allowed Access allowed.\n'
        response += '# TYPE openuds_pool_access_allowed untyped\n'
        response += ('openuds_pool_access_allowed{pool="%s"} %d\n'
                     % (sp_name, int(sp.is_access_allowed() if uds_v4 else sp.isAccessAllowed())))

        response += '# HELP openuds_pool_in_maintenance In maintenance.\n'
        response += '# TYPE openuds_pool_in_maintenance untyped\n'
        response += ('openuds_pool_in_maintenance{pool="%s"} %d\n'
                     % (sp_name, int(sp.is_in_maintenance() if uds_v4 else sp.isInMaintenance())))

        response += '# HELP openuds_pool_restrained Restrained.\n'
        response += '# TYPE openuds_pool_restrained untyped\n'
        response += ('openuds_pool_restrained{pool="%s"} %d\n'
                     % (sp_name, int(sp.is_restrained() if uds_v4 else sp.isRestrained())))

        # openuds_pool settings: initial_srvs, cache_l1, cache_l2, max
        response += '# HELP openuds_pool_initial_srvs Initial services.\n'
        response += '# TYPE openuds_pool_initial_srvs gauge\n'
        response += ('openuds_pool_initial_srvs{pool="%s"} %d\n'
                     % (sp_name, sp.initial_srvs))

        response += '# HELP openuds_pool_cache_l1_srvs L1 cache services.\n'
        response += '# TYPE openuds_pool_cache_l1_srvs gauge\n'
        response += ('openuds_pool_cache_l1_srvs{pool="%s"} %d\n'
                     % (sp_name, sp.cache_l1_srvs))

        response += '# HELP openuds_pool_cache_l2_srvs L2 cache services.\n'
        response += '# TYPE openuds_pool_cache_l2_srvs gauge\n'
        response += ('openuds_pool_cache_l2_srvs{pool="%s"} %d\n'
                     % (sp_name, sp.cache_l2_srvs))

        response += '# HELP openuds_pool_max_srvs Max services.\n'
        response += '# TYPE openuds_pool_max_srvs gauge\n'
        response += ('openuds_pool_max_srvs{pool="%s"} %d\n'
                     % (sp_name, sp.max_srvs))

        # These are serviceProvider metrics, not servicePool ones...
        # move to serviceProvider block?
        try:
            if uds_v4:
                if sp.service.is_type('FPService'):
                    serviceProvider = sp.service.get_instance()
                    response += '# HELP openuds_pool_maximal_srvs Max services.\n'
                    response += '# TYPE openuds_pool_maximal_srvs gauge\n'
                    counter = len(serviceProvider.getFPHosts(serviceProvider.getGroupId()))
                    response += ('openuds_pool_maximal_srvs{pool="%s"} %d\n'
                                 % (sp_name, counter))
            else: #uds_v3
                if sp.service.isOfType('FPService'):
                    serviceProvider = sp.service.getInstance()
                    response += '# HELP openuds_pool_maximal_srvs Max services.\n'
                    response += '# TYPE openuds_pool_maximal_srvs gauge\n'
                    counter = len(serviceProvider.getFPHosts(serviceProvider.getGroupId()))
                    response += ('openuds_pool_maximal_srvs{pool="%s"} %d\n'
                                 % (sp_name, counter))
        except Exception as e:
            date = datetime.datetime.now()
            logger.error('%s - fog project connection error: pool %s - state %s - %s'
                         % (date, sp.name, sp.state, str(e)))

        # openuds_pool state: A (active), .... Whatelse ?
        response += '# HELP openuds_pool_state Pool state.\n'
        response += '# TYPE openuds_pool_state gauge\n'
        response += ('openuds_pool_state{pool="%s", state="A"} %d\n'
                     % (sp_name, int(sp.state == 'A')))
        # here we could put more pool states...
        response += ('openuds_pool_state{pool="%s", state="other"} %d\n'
                     % (sp_name, int(sp.state != 'A')))
        # logging new pool states:
        if sp.state not in 'A':
            date = datetime.datetime.now()
            logger.warning('%s - pool %s - estado %s'
                           % (date, sp.name, sp.state))

        # E. user services
        # names prefix: openuds_pool_userservice_
        if uds_v4:
            cachedUserServices = sp.cached_users_services()
            assignedUserServices = sp.assigned_user_services()
        else: #uds_v3
            erroneousUserServices = sp.erroneousUserServices()
            cachedUserServices = sp.cachedUserServices()
            assignedUserServices = sp.assignedUserServices()
        # restrained is a pool concept, not userservice's one
        # restraineds = sp.getRestraineds()

        # erroneous
        if uds_v3:
            response += ('# HELP openuds_pool_userservice_erroneous_count'
                         ' Pool userservice erroneous counter.\n')
            response += '# TYPE openuds_pool_userservice_erroneous_count gauge\n'
            usl = len([us for us in erroneousUserServices
                      if us.state != 'S'])
            response += ('openuds_pool_userservice_erroneous_count{pool="%s"} %d\n'
                         % (sp_name, usl))
        '''
        # restrained
        response += ('# HELP openuds_pool_userservice_restrained_count'
                     ' Pool userservice restrained counter.\n')
        response += '# TYPE openuds_pool_userservice_restrained_count gauge\n'
        usl = len([us for us in restraineds if us.state != 'S'])
        response += ('openuds_pool_userservice_restrained_count{pool="%s"} %d\n'
                     % (sp_name, usl))
        '''
        # cached
        response += ('# HELP openuds_pool_userservice_cached_count'
                     ' Pool userservice cached counter.\n')
        response += '# TYPE openuds_pool_userservice_cached_count gauge\n'
        usl = len([us for us in cachedUserServices
                  if us.state != 'S'])
        response += ('openuds_pool_userservice_cached_count{pool="%s"} %d\n'
                     % (sp_name, usl))
        # cached_valid_valid
        response += ('# HELP openuds_pool_userservice_cached_valid_valid_count'
                     ' Pool userservice cached valid_valid counter.\n')
        response += '# TYPE openuds_pool_userservice_cached_valid_valid_count gauge\n'
        usl = len([us for us in cachedUserServices
                  if us.state == 'U' and us.os_state == 'U'])
        response += ('openuds_pool_userservice_cached_valid_valid_count{pool="%s"} %d\n'
                     % (sp_name, usl))
        # assigned_inuse
        response += ('# HELP openuds_pool_userservice_assigned_inuse_count'
                     ' Pool userservice assigned_inuse counter.\n')
        response += '# TYPE openuds_pool_userservice_assigned_inuse_count gauge\n'
        usl = len([us for us in assignedUserServices
                  if us.state != 'S' and us.in_use])
        usl_inuse = usl
        response += ('openuds_pool_userservice_assigned_inuse_count{pool="%s"} %d\n'
                     % (sp_name, usl))
        # assigned
        response += ('# HELP openuds_pool_userservice_assigned_count'
                     ' Pool userservice assigned counter.\n')
        response += '# TYPE openuds_pool_userservice_assigned_count gauge\n'
        usl = len([us for us in assignedUserServices
                  if us.state != 'S'])
        response += ('openuds_pool_userservice_assigned_count{pool="%s"} %d\n'
                     % (sp_name, usl))
        # assigned_notinuse:
        # ** this can be calculated by diff so maybe it is bad practice
        #    send it as new metric? but for using it in max_over_time
        #    aggregation function this is convenient (ToDo?)
        response += ('# HELP openuds_pool_userservice_assigned_notinuse_count'
                     ' Pool userservice assigned_notinuse counter.\n')
        response += '# TYPE openuds_pool_userservice_assigned_notinuse_count gauge\n'
        usl_notinuse = usl - usl_inuse
        response += ('openuds_pool_userservice_assigned_notinuse_count{pool="%s"} %d\n'
                     % (sp_name, usl_notinuse))

        # metrics of userservices by states.
        # maybe overkill ?
        # but it's done: if you want them, uncomment it
        """
        nm = 'openuds_pool_userservice'
        response += '# HELP %s Pool userservice by_state counter.\n' % (nm)
        response += '# TYPE %s gauge\n' % (nm)
        known_us_states = []
        for us_state in ['U', 'S', 'R', 'P', 'M', 'C', 'E', 'K']:
            for os_state in ['U', 'P']:
                state = '_'.join([us_state, os_state])
                known_us_states.append(state)

                # erroneous
                usl = len([us for us in erroneousUserServices
                          if '_'.join([us.state, us.os_state]) == state])
                response += ('%s{pool="%s", type="erroneous", state="%s"} %d\n'
                             % (nm, sp_name, state, usl))
                '''
                # restrained
                usl = len([us for us in restraineds
                          if '_'.join([us.state, us.os_state]) == state])
                response += ('%s{pool="%s", type="restrained", state="%s"} %d\n'
                              % (nm, sp_name, state, usl ))
                '''
                # cached
                usl = len([us for us in cachedUserServices
                          if '_'.join([us.state, us.os_state]) == state])
                response += ('%s{pool="%s", type="cached", state="%s"} %d\n'
                             % (nm, sp_name, state, usl))
                # assigned_inuse
                usl = len([us for us in assignedUserServices
                          if '_'.join([us.state, us.os_state]) == state and us.in_use])
                usl_inuse = usl
                response += ('%s{pool="%s", type="assigned_inuse", state="%s"} %d\n'
                             % (nm, sp_name, state, usl))
                # assigned
                usl = len([us for us in assignedUserServices
                          if '_'.join([us.state, us.os_state]) == state])
                response += ('%s{pool="%s", type="assigned", state="%s"} %d\n'
                             % (nm, sp_name, state, usl))

                # assigned_notinuse:
                # ** this can be calculated by diff so maybe it is bad practice
                #    send it as new metric? but for using it in max_over_time
                #    aggregation function this is convenient (ToDo?)
                usl_notinuse = usl - usl_inuse
                response += ('%s{pool="%s", type="assigned_notinuse", state="%s"} %d\n'
                             % (nm, sp_name, state, usl_notinuse))

        # learning userServices not considered states:
        usl = []
        usl.extend([us for us in cachedUserServices
                   if '_'.join([us.state, us.os_state]) not in known_us_states])
        usl.extend([us for us in assignedUserServices
                   if '_'.join([us.state, us.os_state]) not in known_us_states])
        usl.extend([us for us in erroneousUserServices
                   if '_'.join([us.state, us.os_state]) not in known_us_states])
        if len(usl):
            date = datetime.datetime.now()
            new_states = ','.join(['_'.join([us.state, us.os_state]) for us in usl])
            logger.warning('%s - pool %s have userservices in unknown'
                           ' usstate_osstate: %s\n%s'
                           % (date, sp.name, new_states, str(usl)))
        """

    # F. scrapping time
    response += ('# HELP openuds_scrape_collector_duration_seconds'
                 ' Duration of a collector scrape.\n')
    response += '# TYPE openuds_scrape_collector_duration_seconds gauge\n'
    response += ('openuds_scrape_collector_duration_seconds %f\n'
                 % (time.time() - start_time))

    return HttpResponse(response, content_type='text/plain')
