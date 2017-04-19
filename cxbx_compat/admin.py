from django.contrib import admin
from django.db.models import Count, Max, Min
from django.utils.html import format_html
from django.utils.http import urlencode

from .models import Build, Game, Title, Executable, XDKLibrary


class TitleInline(admin.StackedInline):
    model = Title
    extra = 0

    readonly_fields = ['executables']
    fields = ['executables']

    def executables(self, obj):
        return format_html('<a href="../../../executable/?q={}">{}</a>', obj.title_id, obj.exes)

    def get_queryset(self, request):
        qs = super(TitleInline, self).get_queryset(request)
        qs = qs.annotate(exes=Count('executable'))

        return qs


class XDKLibraryInline(admin.TabularInline):
    model = Executable.xdk_libraries.through
    extra = 0
    verbose_name = 'XDK Library'
    verbose_name_plural = 'XDK Libraries'

    fields = ['name', 'xdk_version']
    readonly_fields = ('name', 'xdk_version',)

    def xdk_version(self, obj):
        return '{0}.{1}'.format(obj.xdklibrary.xdk_version, obj.xdklibrary.qfe_version)

    def name(self, obj):
        return obj.xdklibrary.name

    def get_queryset(self, request):
        qs = super(XDKLibraryInline, self).get_queryset(request)
        qs = qs.prefetch_related('xdklibrary')
        return qs


class GameAdmin(admin.ModelAdmin):
    list_display = ('name', 'titles', 'exes')
    search_fields = ('name',)

    inlines = [TitleInline]

    def titles(self, obj):
        return format_html('<a href="../title/?q={}">{}</a>', obj.name, obj.titles)
    
    titles.admin_order_field = 'titles'
    
    def exes(self, obj):
        return format_html('<a href="../executable/?q={}">{}</a>', obj.name, obj.exes)
    
    exes.admin_order_field = 'exes'
    
    def get_queryset(self, request):
        qs = super(GameAdmin, self).get_queryset(request)
        qs = qs.annotate(titles=Count('title', distinct=True), exes=Count('title__executable'))
        return qs


class ExecutableInline(admin.TabularInline):
    model = Executable.xdk_libraries.through
    dir(model)
    extra = 0

    verbose_name = 'Executable'
    verbose_name_plural = 'Executables'

    readonly_fields = ['game', 'title', 'xbe']

    fields = ['xbe', 'game', 'title', ]

    def game(self, obj):
        return format_html('<a href="../../../game/{}">{}</a>',
                           obj.executable.title.game.id,
                           obj.executable.title.game.name
                           )

    def title(self, obj):
        return format_html('<a href="../../../title/{}">[{}]</a>''',
                           obj.executable.title.id,
                           obj.executable.title.title_id,
                           )

    def xbe(self, obj):
        return format_html('<a href="../../../executable/{}">{}{}</a>',
                           obj.executable.id,
                           obj.executable.disk_path,
                           obj.executable.file_name,
                           )

    def get_queryset(self, request):
        qs = super(ExecutableInline, self).get_queryset(request)
        qs = qs.prefetch_related('executable').prefetch_related('executable__title')
        qs = qs.prefetch_related('executable__title__game')
        return qs


class ExecutableInlineT(admin.TabularInline):
    model = Executable

    extra = 0

    fields = ['xbe', 'libraries', 'min_version', 'max_version']
    readonly_fields = fields

    def get_queryset(self, request):
        qs = super(ExecutableInlineT, self).get_queryset(request).annotate(
            libraries=Count('xdk_libraries'),
            max_version=Max('xdk_libraries__xdk_version'),
            min_version=Min('xdk_libraries__xdk_version')
        )
        return qs

    def libraries(self, obj):
        return obj.libraries

    def max_version(self, obj):
        return obj.max_version

    def min_version(self, obj):
        return obj.min_version

    def xbe(self, obj):
        return format_html('<a href="../../../executable/{}">View more</a>', obj.id)


class XDKLibraryAdmin(admin.ModelAdmin):
    list_display = ('name', 'xdk_version', 'qfe_version', 'exes')
    list_filter = ('name', 'xdk_version')

    inlines = [ExecutableInline]

    fieldsets = (
        (None, {
            'fields': ('name', 'xdk_version', 'qfe_version',),
        }),
    )

    search_fields = ('name', 'xdk_version')

    def exes(self, obj):
        return format_html('<a href="{}">{}</a>', obj.id, obj.exes)

    exes.admin_order_field = 'exes'

    def get_queryset(self, request):
        qs = super(XDKLibraryAdmin, self).get_queryset(request)
        qs = qs.annotate(exes=Count('executable'))
        return qs


class ExecutableAdmin(admin.ModelAdmin):
    list_display = ('executable', 'title_name', 'min_xdk', 'max_xdk', 'libraries')
    search_fields = ('file_name', 'title__game__name', 'title__title_id')

    fieldsets = (
        (None, {
            'fields': ('title', ('disk_path', 'file_name',), ('signature', 'signature_status'))
        }),
        ('Original info file', {
            'classes': ['collapse'],
            'fields': ('formatted_xbe_info',),
        })
    )

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "title":
            kwargs['queryset'] = Title.objects.all().select_related('game')
        return super(ExecutableAdmin, self).formfield_for_foreignkey(db_field, request, **kwargs)

    readonly_fields = ('formatted_xbe_info',)

    inlines = [XDKLibraryInline]

    def executable(self, obj):
        return str(obj)

    def formatted_xbe_info(self, obj):
        return format_html('<pre>\r\n\r\n{}</pre>', obj.xbe_info)

    def get_queryset(self, request):
        qs = super(ExecutableAdmin, self).get_queryset(request)
        qs = qs.annotate(
            libraries=Count('xdk_libraries'),
            max_version=Max('xdk_libraries__xdk_version'),
            min_version=Min('xdk_libraries__xdk_version')
        )
        qs = qs.prefetch_related('title').prefetch_related('title__game')
        return qs

    def min_xdk(self, obj):
        return obj.min_version

    def max_xdk(self, obj):
        return obj.max_version

    def libraries(self, obj):
        return obj.libraries

    def title_name(self, obj):
        return format_html('<a href="../game/{}">{}</a> [<a href="../title/{}">{}</a>]', obj.title.game.id, obj.title.game.name, obj.title.id, obj.title.title_id)

    formatted_xbe_info.short_description = ''
    min_xdk.admin_order_field = 'min_version'
    max_xdk.admin_order_field = 'max_version'
    libraries.admin_order_field = 'libraries'
    title_name.admin_order_field = 'title__game__name'


class TitleAdmin(admin.ModelAdmin):
    list_display = ('title_id', 'game_name', 'exes')
    search_fields = ('title_id', 'game__name')

    inlines = [ExecutableInlineT]

    def exes(self, obj):
        return format_html('<a href="../executable/?q={}">{}</a>', obj.title_id, obj.exes)

    def game_name(self, obj):
        return format_html('<a href="../game/{}">{}</a>', obj.game.id, obj.game.name)

    def get_queryset(self, request):
        qs = super(TitleAdmin, self).get_queryset(request)
        qs = qs.annotate(exes=Count('executable'))
        qs = qs.prefetch_related('game')
        return qs

    exes.admin_order_field = 'exes'
    game_name.admin_order_field = 'game__name'

admin.site.register(Build)
admin.site.register(Game, GameAdmin)
admin.site.register(Title, TitleAdmin)
admin.site.register(Executable, ExecutableAdmin)
admin.site.register(XDKLibrary, XDKLibraryAdmin)

