# aws_security_scanner/scanners/cloudfront_scanner.py
from ..core.base_scanner import BaseScanner
from ..core.exceptions import ScannerError
from typing import Dict, List, Any

class CloudFrontScanner(BaseScanner):
    """Scanner for CloudFront service"""

    async def scan(self) -> None:
        """Scan CloudFront distributions for security issues"""
        try:
            cloudfront = self.session.client('cloudfront')
            distributions = await self._get_all_distributions(cloudfront)

            for distribution in distributions:
                await self._scan_ssl_configuration(distribution)
                await self._scan_security_headers(distribution)
                await self._scan_origins(distribution)
                await self._scan_geo_restrictions(distribution)
                await self._scan_waf_integration(distribution)
                await self._scan_logging_config(distribution)
                await self._scan_viewer_protocol_policy(distribution)
        except Exception as e:
            raise ScannerError(f"CloudFront scan failed: {str(e)}")

    async def _get_all_distributions(self, cloudfront) -> List[Dict[str, Any]]:
        """Get all CloudFront distributions"""
        distributions = []
        paginator = cloudfront.get_paginator('list_distributions')
        async for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])
        return distributions

    async def _scan_ssl_configuration(self, distribution: Dict[str, Any]) -> None:
        """Check SSL/TLS configuration"""
        viewer_cert = distribution.get('ViewerCertificate', {})

        # Check for outdated SSL protocols
        if viewer_cert.get('MinimumProtocolVersion', '') in ['SSLv3', 'TLSv1', 'TLSv1_2016']:
            risk_factors = {
                'tls_configuration': 8,
                'protocol_security': 7
            }

            self.add_finding(
                service="CloudFront",
                resource=f"Distribution/{distribution['Id']}",
                risk_factors=risk_factors,
                description="Distribution uses outdated SSL/TLS protocol",
                recommendation="Upgrade to minimum TLSv1.2"
            )

    async def _scan_security_headers(self, distribution: Dict[str, Any]) -> None:
        """Check security headers configuration"""
        behaviors = distribution.get('DefaultCacheBehavior', {})
        headers = behaviors.get('ResponseHeadersPolicyId')

        if not headers:
            risk_factors = {
                'headers_security': 6,
                'best_practice': 5
            }

            self.add_finding(
                service="CloudFront",
                resource=f"Distribution/{distribution['Id']}",
                risk_factors=risk_factors,
                description="No security headers policy configured",
                recommendation="Configure security headers policy with HSTS, CSP, etc."
            )

    async def _scan_origins(self, distribution: Dict[str, Any]) -> None:
        """Check origin configurations"""
        origins = distribution.get('Origins', {}).get('Items', [])

        for origin in origins:
            # Check for S3 origin access identity
            if 's3' in origin.get('DomainName', '').lower():
                if not origin.get('S3OriginConfig', {}).get('OriginAccessIdentity'):
                    risk_factors = {
                        'access_control': 7,
                        'security_configuration': 6
                    }

                    self.add_finding(
                        service="CloudFront",
                        resource=f"Distribution/{distribution['Id']}/Origin/{origin['Id']}",
                        risk_factors=risk_factors,
                        description="S3 origin not using Origin Access Identity",
                        recommendation="Configure Origin Access Identity for S3 buckets"
                    )

    
# Continuing aws_security_scanner/scanners/cloudfront_scanner.py

    async def _scan_geo_restrictions(self, distribution: Dict[str, Any]) -> None:
        """Check geographic restrictions"""
        restrictions = distribution.get('Restrictions', {}).get('GeoRestriction', {})

        if restrictions.get('RestrictionType') == 'none':
            risk_factors = {
                'access_control': 5,
                'geographic_security': 4
            }

            self.add_finding(
                service="CloudFront",
                resource=f"Distribution/{distribution['Id']}",
                risk_factors=risk_factors,
                description="No geographic restrictions configured",
                recommendation="Configure geographic restrictions to limit content access"
            )

    async def _scan_waf_integration(self, distribution: Dict[str, Any]) -> None:
        """Check WAF integration"""
        if not distribution.get('WebACLId'):
            risk_factors = {
                'web_security': 8,
                'attack_prevention': 7
            }

            self.add_finding(
                service="CloudFront",
                resource=f"Distribution/{distribution['Id']}",
                risk_factors=risk_factors,
                description="No WAF web ACL associated",
                recommendation="Configure AWS WAF to protect against web attacks"
            )

    async def _scan_logging_config(self, distribution: Dict[str, Any]) -> None:
        """Check logging configuration"""
        logging = distribution.get('Logging', {})

        if not logging.get('Enabled'):
            risk_factors = {
                'monitoring': 6,
                'audit': 5
            }

            self.add_finding(
                service="CloudFront",
                resource=f"Distribution/{distribution['Id']}",
                risk_factors=risk_factors,
                description="Access logging is not enabled",
                recommendation="Enable access logging for audit and monitoring"
            )

    async def _scan_viewer_protocol_policy(self, distribution: Dict[str, Any]) -> None:
        """Check viewer protocol policy"""
        default_behavior = distribution.get('DefaultCacheBehavior', {})
        cache_behaviors = distribution.get('CacheBehaviors', {}).get('Items', [])

        # Check default behavior
        if default_behavior.get('ViewerProtocolPolicy') != 'https-only':
            risk_factors = {
                'protocol_security': 7,
                'data_protection': 6
            }

            self.add_finding(
                service="CloudFront",
                resource=f"Distribution/{distribution['Id']}",
                risk_factors=risk_factors,
                description="Default cache behavior allows non-HTTPS traffic",
                recommendation="Set viewer protocol policy to HTTPS only"
            )

        # Check other cache behaviors
        for behavior in cache_behaviors:
            if behavior.get('ViewerProtocolPolicy') != 'https-only':
                risk_factors = {
                    'protocol_security': 7,
                    'data_protection': 6
                }

                self.add_finding(
                    service="CloudFront",
                    resource=f"Distribution/{distribution['Id']}/CacheBehavior/{behavior.get('PathPattern')}",
                    risk_factors=risk_factors,
                    description=f"Cache behavior for {behavior.get('PathPattern')} allows non-HTTPS traffic",
                    recommendation="Set viewer protocol policy to HTTPS only"
                )

    def _is_insecure_origin_protocol(self, origin: Dict[str, Any]) -> bool:
        """Check if origin uses insecure protocol"""
        custom_origin = origin.get('CustomOriginConfig', {})
        if custom_origin:
            protocols = custom_origin.get('OriginProtocolPolicy', '')
            return protocols in ['http-only', 'match-viewer']
        return False

    def _has_field_level_encryption(self, distribution: Dict[str, Any]) -> bool:
        """Check if field-level encryption is configured"""
        default_behavior = distribution.get('DefaultCacheBehavior', {})
        return bool(default_behavior.get('FieldLevelEncryptionId'))
